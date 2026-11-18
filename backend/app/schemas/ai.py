"""Pydantic schemas for the AI API — Phase 6.

Analysis output is the EXACT 10-section structure defined in
``docs/AI_PIPELINE.md``; sections are validated here so a provider
reply missing a section is rejected (and the caller falls back to
the rule-based analysis).
"""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

ANALYSIS_TYPES = (
    "simple",
    "advanced",
    "impact",
    "affected_systems",
    "root_cause",
    "attack_scenarios",
    "verification",
    "remediation",
    "prevention",
    "assessment",
)

AnalysisType = Literal[
    "simple",
    "advanced",
    "impact",
    "affected_systems",
    "root_cause",
    "attack_scenarios",
    "verification",
    "remediation",
    "prevention",
    "assessment",
]


class ReferenceItem(BaseModel):
    label: str
    url: str


class ConfidenceAndLimitations(BaseModel):
    confidence: str = "low"
    limitations: list[str] = Field(default_factory=list)


class AnalysisSections(BaseModel):
    """The exact 10-section analysis structure."""

    executive_summary: str
    technical_explanation: str
    root_cause: str
    potential_impact: str
    affected_components: str
    risk_assessment: str
    defensive_verification: str
    remediation: str
    references: list[ReferenceItem] = Field(default_factory=list)
    confidence_and_limitations: ConfidenceAndLimitations

    model_config = {"extra": "ignore"}


class AnalyzeRequest(BaseModel):
    cve_id: str = Field(min_length=1, max_length=32)
    analysis_type: AnalysisType = "simple"


class AnalyzeResponse(BaseModel):
    cve_id: str
    analysis_type: str
    ai_mode: Literal["provider", "fallback"]
    model: str | None = None
    fallback_reason: str | None = None
    analysis: AnalysisSections
    citations: list[dict[str, Any]] = Field(default_factory=list)


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    conversation_id: uuid.UUID | None = None


class ChatResponse(BaseModel):
    answer: str
    citations: list[dict[str, Any]] = Field(default_factory=list)
    conversation_id: uuid.UUID
    ai_mode: Literal["provider", "fallback"]
    model: str | None = None


class ConversationMessageOut(BaseModel):
    id: uuid.UUID
    role: str
    content: str
    citations: list[dict[str, Any]] | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ConversationSummary(BaseModel):
    id: uuid.UUID
    title: str | None
    created_at: datetime
    updated_at: datetime
    message_count: int = 0

    model_config = {"from_attributes": True}


class ConversationDetail(BaseModel):
    id: uuid.UUID
    title: str | None
    created_at: datetime
    updated_at: datetime
    messages: list[ConversationMessageOut] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class AIStatusResponse(BaseModel):
    provider_configured: bool
    provider: str | None
    mode: Literal["provider", "fallback"]
