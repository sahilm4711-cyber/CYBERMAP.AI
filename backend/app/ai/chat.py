"""AI research assistant chat — Phase 6.

``answer_question`` validates the question, fetches any CVE records
named in it first (regex ``CVE-\\d{4}-\\d{4,7}``), otherwise
RAG-retrieves the top 5 records, then answers via the configured
provider or the extractive fallback.

Fallback rules:
- Extractive only: the answer is assembled from DB facts
  (CVE/CWE/technique records) with citations — never invented.
- If retrieval returns nothing, the answer says so plainly
  ("I found no indexed records matching that question") — never
  pretend a search happened.
- Retrieved chunk text is data, not instructions: the fallback
  never echoes raw chunk text and never obeys instructions embedded
  in it; it only reports structured record facts.
"""

import re
import uuid

from sqlalchemy.orm import Session

from app.ai.adapters import AIProviderError, get_adapter
from app.ai.embeddings import retrieve
from app.ai.rag import build_grounded_messages
from app.models import (
    AttackTechnique,
    Conversation,
    ConversationMessage,
    CweEntry,
    User,
    Vulnerability,
)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
MAX_QUESTION_CHARS = 2000
NO_RECORDS_MESSAGE = "I found no indexed records matching that question."

# Titles are derived from the first question, truncated.
TITLE_MAX_CHARS = 60


class ConversationNotFoundError(Exception):
    """Conversation id missing or owned by another user."""


class InvalidQuestionError(ValueError):
    """Question is empty or over the length limit."""


def _citation_for_vuln(vuln: Vulnerability) -> dict:
    return {
        "cve_id": vuln.cve_id,
        "source": vuln.source,
        "url": vuln.source_url,
    }


def _citation_for_cwe(cwe: CweEntry) -> dict:
    return {
        "cwe_id": cwe.cwe_id,
        "source": cwe.source,
        "url": cwe.source_url,
    }


def _citation_for_technique(tech: AttackTechnique) -> dict:
    return {
        "technique_id": tech.technique_id,
        "source": tech.source,
        "url": tech.source_url,
    }


def _record_summary_vuln(vuln: Vulnerability) -> str:
    cvss = (
        f"CVSS {float(vuln.cvss_score):.1f}"
        if vuln.cvss_score is not None
        else "CVSS not available"
    )
    severity = vuln.severity or "severity unknown"
    return (
        f"{vuln.cve_id} ({severity}, {cvss}): "
        f"{vuln.description or 'No description recorded.'}"
    )


def _record_summary_cwe(cwe: CweEntry) -> str:
    return (
        f"{cwe.cwe_id} {cwe.name}: {cwe.description or 'No description recorded.'}"
    )


def _record_summary_technique(tech: AttackTechnique) -> str:
    tactic = f" ({tech.tactic})" if tech.tactic else ""
    return (
        f"{tech.technique_id} {tech.name}{tactic}: "
        f"{tech.description or 'No description recorded.'}"
    )


def _load_rag_records(db: Session, retrieved: list[dict]):
    """Resolve RAG hits back to DB records (facts, not chunk text)."""
    vulns: list[Vulnerability] = []
    cwes: list[CweEntry] = []
    techniques: list[AttackTechnique] = []
    for item in retrieved:
        if item["entity_type"] == "vulnerability":
            rec = db.query(Vulnerability).filter(
                Vulnerability.id == item["entity_id"]
            ).first()
            if rec is not None:
                vulns.append(rec)
        elif item["entity_type"] == "cwe":
            rec = db.query(CweEntry).filter(
                CweEntry.id == item["entity_id"]
            ).first()
            if rec is not None:
                cwes.append(rec)
        elif item["entity_type"] == "attack_technique":
            rec = db.query(AttackTechnique).filter(
                AttackTechnique.id == item["entity_id"]
            ).first()
            if rec is not None:
                techniques.append(rec)
    return vulns, cwes, techniques


def _fallback_answer(
    vulns: list[Vulnerability],
    cwes: list[CweEntry],
    techniques: list[AttackTechnique],
) -> tuple[str, list[dict]]:
    """Extractive fallback answer from DB records only."""
    if not vulns and not cwes and not techniques:
        return NO_RECORDS_MESSAGE, []
    parts = [
        "Based on the indexed records (rule-based summary — no AI "
        "provider configured):"
    ]
    citations: list[dict] = []
    for vuln in vulns:
        parts.append(_record_summary_vuln(vuln))
        citations.append(_citation_for_vuln(vuln))
    for cwe in cwes:
        parts.append(_record_summary_cwe(cwe))
        citations.append(_citation_for_cwe(cwe))
    for tech in techniques:
        parts.append(_record_summary_technique(tech))
        citations.append(_citation_for_technique(tech))
    return "\n\n".join(parts), citations


def answer_question(
    db: Session,
    user: User,
    conversation_id: uuid.UUID | str | None,
    question: str,
) -> dict:
    """Answer ``question``; persist both messages; return the envelope.

    ``{answer, citations, conversation_id, ai_mode, model}``.
    """
    if question is None or not question.strip():
        raise InvalidQuestionError("Question must not be empty")
    if len(question) > MAX_QUESTION_CHARS:
        raise InvalidQuestionError(
            f"Question must be at most {MAX_QUESTION_CHARS} characters"
        )
    question = question.strip()

    # -- conversation (create or load + ownership check) -------------
    conversation: Conversation | None = None
    if conversation_id is not None:
        conversation = (
            db.query(Conversation)
            .filter(Conversation.id == conversation_id)
            .first()
        )
        if conversation is None or conversation.user_id != user.id:
            raise ConversationNotFoundError(
                "Conversation not found"
            )
    if conversation is None:
        conversation = Conversation(
            user_id=user.id,
            title=question[:TITLE_MAX_CHARS],
        )
        db.add(conversation)
        db.commit()
        db.refresh(conversation)

    # -- gather grounded records --------------------------------------
    cve_ids = list(dict.fromkeys(CVE_RE.findall(question)))
    vulns: list[Vulnerability] = []
    cwes: list[CweEntry] = []
    techniques: list[AttackTechnique] = []
    rag_results: list[dict] = []
    if cve_ids:
        for cve_id in cve_ids:
            vuln = (
                db.query(Vulnerability)
                .filter(
                    Vulnerability.cve_id == cve_id.upper()
                )
                .first()
            )
            if vuln is not None:
                vulns.append(vuln)
    else:
        rag_results = retrieve(db, question, top_k=5)
        vulns, cwes, techniques = _load_rag_records(db, rag_results)

    citations: list[dict] = []
    answer: str
    ai_mode = "fallback"
    model: str | None = None

    adapter = None
    try:
        adapter = get_adapter()
    except ValueError:
        adapter = None

    if adapter is not None:
        # Provider mode: grounded prompt over the same records.
        grounded_records: list[dict] = []
        for vuln in vulns:
            grounded_records.append(
                {
                    "entity_type": "vulnerability",
                    "entity_id": vuln.id,
                    "chunk_text": _record_summary_vuln(vuln),
                    "score": 1.0,
                    "source_url": vuln.source_url,
                }
            )
        for cwe in cwes:
            grounded_records.append(
                {
                    "entity_type": "cwe",
                    "entity_id": cwe.id,
                    "chunk_text": _record_summary_cwe(cwe),
                    "score": 1.0,
                    "source_url": cwe.source_url,
                }
            )
        for tech in techniques:
            grounded_records.append(
                {
                    "entity_type": "attack_technique",
                    "entity_id": tech.id,
                    "chunk_text": _record_summary_technique(tech),
                    "score": 1.0,
                    "source_url": tech.source_url,
                }
            )
        grounded_records.extend(rag_results)
        try:
            messages = build_grounded_messages(
                question,
                grounded_records,
                system_prompt=(
                    "You are a security research assistant. Answer "
                    "only from the provided database facts and "
                    "retrieved context, and cite the records used."
                ),
            )
            answer = adapter.chat(messages)
            ai_mode = "provider"
            model = adapter.model
            citations = [
                _citation_for_vuln(v) for v in vulns
            ] + [
                _citation_for_cwe(c) for c in cwes
            ] + [
                _citation_for_technique(t) for t in techniques
            ]
            if not citations and rag_results:
                citations = [
                    {
                        "source": item["entity_type"],
                        "url": item.get("source_url"),
                    }
                    for item in rag_results
                ]
            if not vulns and not cwes and not techniques and not rag_results:
                answer = NO_RECORDS_MESSAGE
        except (AIProviderError, ValueError):
            answer, citations = _fallback_answer(vulns, cwes, techniques)
            ai_mode = "fallback"
            model = None
    else:
        answer, citations = _fallback_answer(vulns, cwes, techniques)

    # -- persist both messages ----------------------------------------
    db.add(
        ConversationMessage(
            conversation_id=conversation.id,
            role="user",
            content=question,
            citations=None,
        )
    )
    db.add(
        ConversationMessage(
            conversation_id=conversation.id,
            role="assistant",
            content=answer,
            citations=citations or None,
        )
    )
    db.commit()

    return {
        "answer": answer,
        "citations": citations,
        "conversation_id": conversation.id,
        "ai_mode": ai_mode,
        "model": model,
    }
