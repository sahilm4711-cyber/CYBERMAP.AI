"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import {
  deleteConversation,
  getAiStatus,
  getConversation,
  listConversations,
  sendChat,
  type AiStatus,
  type ChatMessage,
  type Citation,
  type ConversationSummary,
} from "@/lib/services/ai";
import { ApiError } from "@/lib/services/client";

function Citations({ citations }: { citations: Citation[] }) {
  if (!citations.length) return null;
  return (
    <div className="mt-2 flex flex-wrap gap-2">
      {citations.map((c, i) => {
        const label =
          c.cve_id ?? c.cwe_id ?? c.technique_id ?? c.source ?? "source";
        const key = `${label}-${c.url ?? i}`;
        return c.url ? (
          <a
            key={key}
            href={c.url}
            target="_blank"
            rel="noreferrer"
            className="rounded-full border border-cyan-800 bg-cyan-950/40 px-2 py-0.5 text-xs text-cyan-300 hover:bg-cyan-900/40"
          >
            {label}
          </a>
        ) : (
          <span
            key={key}
            className="rounded-full border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-xs text-zinc-300"
          >
            {label}
          </span>
        );
      })}
    </div>
  );
}

export default function AiAssistantPage() {
  const [conversations, setConversations] = useState<
    ConversationSummary[]
  >([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [question, setQuestion] = useState("");
  const [status, setStatus] = useState<AiStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unauthorized, setUnauthorized] = useState(false);

  const refreshList = useCallback(async () => {
    const list = await listConversations();
    setConversations(list);
    return list;
  }, []);

  useEffect(() => {
    let cancelled = false;
    Promise.all([getAiStatus(), listConversations()])
      .then(([st, list]) => {
        if (cancelled) return;
        setStatus(st);
        setConversations(list);
        setLoading(false);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 401) {
          setUnauthorized(true);
        } else {
          setError(
            err instanceof Error
              ? err.message
              : "Could not reach the backend.",
          );
        }
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function openConversation(id: string) {
    setSelectedId(id);
    setError(null);
    try {
      const detail = await getConversation(id);
      setMessages(detail.messages);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not load conversation.",
      );
    }
  }

  function newChat() {
    setSelectedId(null);
    setMessages([]);
    setError(null);
  }

  async function onDelete(id: string) {
    try {
      await deleteConversation(id);
      setConversations((prev) => prev.filter((c) => c.id !== id));
      if (selectedId === id) newChat();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not delete conversation.",
      );
    }
  }

  async function onSend(e: React.FormEvent) {
    e.preventDefault();
    const q = question.trim();
    if (!q || sending) return;
    setError(null);
    setSending(true);
    // Show the question immediately; the answer replaces the wait.
    const optimistic: ChatMessage = {
      id: `local-${Date.now()}`,
      role: "user",
      content: q,
      citations: null,
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, optimistic]);
    setQuestion("");
    try {
      const res = await sendChat({
        question: q,
        conversation_id: selectedId,
      });
      setMessages((prev) => [
        ...prev,
        {
          id: `assistant-${res.conversation_id}-${Date.now()}`,
          role: "assistant",
          content: res.answer,
          citations: res.citations,
          created_at: new Date().toISOString(),
        },
      ]);
      setSelectedId(res.conversation_id);
      await refreshList();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setUnauthorized(true);
      } else {
        setError(
          err instanceof Error ? err.message : "Could not send question.",
        );
      }
    } finally {
      setSending(false);
    }
  }

  if (loading) {
    return (
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 text-sm text-zinc-400">
        Loading AI assistant…
      </div>
    );
  }

  if (unauthorized) {
    return (
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-6">
        <h1 className="text-xl font-bold">AI Assistant</h1>
        <p className="mt-2 text-sm text-zinc-400">
          Log in to ask the research assistant about indexed
          vulnerabilities.
        </p>
        <Link
          href="/login"
          className="mt-4 inline-block rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-500"
        >
          Log in
        </Link>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 lg:flex-row">
      <aside className="w-full shrink-0 lg:w-64">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold tracking-tight">
            AI Assistant
          </h1>
          <button
            onClick={newChat}
            className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-200 hover:bg-zinc-800"
          >
            New chat
          </button>
        </div>
        <p className="mt-1 text-xs text-zinc-500">
          Mode:{" "}
          {status
            ? `${status.mode}${status.provider ? ` (${status.provider})` : " — rule-based fallback, no AI provider configured"}`
            : "unknown"}
        </p>
        <ul className="mt-4 flex flex-col gap-2">
          {conversations.length === 0 ? (
            <li className="rounded-xl border border-dashed border-zinc-700 p-3 text-sm text-zinc-500">
              No conversations yet. Ask a question to start one.
            </li>
          ) : (
            conversations.map((c) => (
              <li key={c.id}>
                <div
                  className={`flex items-center justify-between gap-2 rounded-xl border px-3 py-2 text-sm ${
                    selectedId === c.id
                      ? "border-cyan-700 bg-cyan-950/30 text-zinc-100"
                      : "border-zinc-800 bg-zinc-900/60 text-zinc-300"
                  }`}
                >
                  <button
                    onClick={() => void openConversation(c.id)}
                    className="min-w-0 flex-1 truncate text-left"
                  >
                    {c.title ?? "Untitled conversation"}
                    <span className="block text-xs text-zinc-500">
                      {c.message_count} messages
                    </span>
                  </button>
                  <button
                    onClick={() => void onDelete(c.id)}
                    aria-label="Delete conversation"
                    className="shrink-0 text-xs text-zinc-500 hover:text-red-400"
                  >
                    Delete
                  </button>
                </div>
              </li>
            ))
          )}
        </ul>
      </aside>

      <section className="min-w-0 flex-1">
        {error ? (
          <div className="mb-4 rounded-xl border border-red-900 bg-red-950/40 p-4 text-sm text-red-200">
            {error}
          </div>
        ) : null}
        <div className="flex flex-col gap-4">
          {messages.length === 0 ? (
            <div className="rounded-xl border border-dashed border-zinc-700 bg-zinc-900/30 p-5 text-sm text-zinc-400">
              Ask about an indexed vulnerability — for example,
              “Tell me about CVE-2024-44444.” Answers come only from
              indexed records and cite them; with no AI provider
              configured you get a rule-based summary instead.
            </div>
          ) : (
            messages.map((m) => (
              <div
                key={m.id}
                className={`rounded-xl border p-4 ${
                  m.role === "user"
                    ? "border-zinc-800 bg-zinc-900/60"
                    : "border-cyan-900/60 bg-cyan-950/20"
                }`}
              >
                <p className="text-xs uppercase tracking-wide text-zinc-500">
                  {m.role === "user" ? "You" : "Assistant"}
                </p>
                <p className="mt-1 whitespace-pre-wrap text-sm leading-6 text-zinc-100">
                  {m.content}
                </p>
                {m.role === "assistant" ? (
                  <Citations citations={m.citations ?? []} />
                ) : null}
              </div>
            ))
          )}
        </div>
        <form onSubmit={onSend} className="mt-4 flex gap-2">
          <input
            className="min-w-0 flex-1 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-cyan-500 focus:outline-none"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask about a CVE, CWE or technique…"
            maxLength={2000}
          />
          <button
            type="submit"
            disabled={sending || !question.trim()}
            className="shrink-0 rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
          >
            {sending ? "Asking…" : "Ask"}
          </button>
        </form>
      </section>
    </div>
  );
}
