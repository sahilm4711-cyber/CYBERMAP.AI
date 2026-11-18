"use client";

import { useState } from "react";
import { useTopic, useTopics } from "@/lib/hooks/useLearning";

type Level = "beginner" | "intermediate" | "advanced";

const LEVELS: { key: Level; label: string }[] = [
  { key: "beginner", label: "Beginner" },
  { key: "intermediate", label: "Intermediate" },
  { key: "advanced", label: "Advanced" },
];

export default function LearningPage() {
  const { topics, loading, error } = useTopics();
  const [selected, setSelected] = useState<string | null>(null);
  const [level, setLevel] = useState<Level>("beginner");
  const [answers, setAnswers] = useState<Record<number, number>>({});
  const detail = useTopic(selected);

  function pickTopic(slug: string) {
    setSelected(slug);
    setAnswers({});
    setLevel("beginner");
  }

  return (
    <div className="flex flex-col gap-8">
      <section>
        <h1 className="text-3xl font-bold tracking-tight">Security Learning Center</h1>
        <p className="mt-2 max-w-2xl text-zinc-400">
          Short, defensive lessons on the weaknesses behind real
          vulnerabilities — what they are, how to prevent them, and how to
          fix them. No exploit payloads: the examples show the safe way to
          build.
        </p>
      </section>

      {error && (
        <div className="rounded-xl border border-red-900 bg-red-950/40 p-4 text-sm text-red-200">
          {error}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
        {/* Topic list */}
        <nav aria-label="Topics" className="flex flex-col gap-2">
          {loading ? (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 text-sm text-zinc-400">
              Loading topics…
            </div>
          ) : (topics ?? []).length === 0 ? (
            <p className="text-sm text-zinc-500">No topics available.</p>
          ) : (
            topics?.map((t) => (
              <button
                key={t.slug}
                onClick={() => pickTopic(t.slug)}
                className={`rounded-xl border p-3 text-left text-sm ${
                  selected === t.slug
                    ? "border-cyan-600 bg-cyan-950/40 text-cyan-100"
                    : "border-zinc-800 bg-zinc-900/60 text-zinc-200 hover:border-zinc-600"
                }`}
              >
                {t.title}
              </button>
            ))
          )}
        </nav>

        {/* Topic detail */}
        <section aria-label="Topic detail">
          {!selected ? (
            <div className="rounded-xl border border-dashed border-zinc-700 bg-zinc-900/30 p-5 text-sm text-zinc-400">
              Pick a topic on the left to start learning.
            </div>
          ) : detail.loading ? (
            <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 text-sm text-zinc-400">
              Loading topic…
            </div>
          ) : detail.error ? (
            <div className="rounded-xl border border-red-900 bg-red-950/40 p-4 text-sm text-red-200">
              {detail.error}
            </div>
          ) : detail.topic ? (
            <article className="flex flex-col gap-6">
              <h2 className="text-2xl font-semibold">{detail.topic.title}</h2>

              <div className="flex gap-2" role="tablist" aria-label="Level">
                {LEVELS.map((l) => (
                  <button
                    key={l.key}
                    role="tab"
                    aria-selected={level === l.key}
                    onClick={() => setLevel(l.key)}
                    className={`rounded-lg px-3 py-1 text-sm ${
                      level === l.key
                        ? "bg-cyan-600 text-white"
                        : "border border-zinc-700 text-zinc-300"
                    }`}
                  >
                    {l.label}
                  </button>
                ))}
              </div>
              <p className="leading-7 text-zinc-300">
                {detail.topic.levels[level]}
              </p>

              <div>
                <h3 className="font-semibold">Key points</h3>
                <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-zinc-300">
                  {detail.topic.key_points.map((point) => (
                    <li key={point}>{point}</li>
                  ))}
                </ul>
              </div>

              <div>
                <h3 className="font-semibold">Defensive examples</h3>
                <div className="mt-2 flex flex-col gap-3">
                  {detail.topic.defensive_examples.map((ex) => (
                    <div
                      key={ex.title}
                      className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4"
                    >
                      <p className="text-sm font-semibold">{ex.title}</p>
                      <pre className="mt-2 overflow-x-auto rounded-lg bg-black/60 p-3 font-mono text-xs leading-5 text-zinc-200">
                        {ex.code}
                      </pre>
                      <p className="mt-2 text-sm text-zinc-400">{ex.explanation}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h3 className="font-semibold">Knowledge check</h3>
                <div className="mt-2 flex flex-col gap-4">
                  {detail.topic.knowledge_check.map((q, qi) => {
                    const chosen = answers[qi];
                    const correct = chosen === q.answer_index;
                    return (
                      <div
                        key={q.question}
                        className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4"
                      >
                        <p className="text-sm font-medium">{q.question}</p>
                        <div className="mt-3 flex flex-col gap-2">
                          {q.options.map((opt, oi) => {
                            const isAnswer = oi === q.answer_index;
                            const isChosen = oi === chosen;
                            return (
                              <button
                                key={opt}
                                onClick={() =>
                                  setAnswers((prev) => ({ ...prev, [qi]: oi }))
                                }
                                className={`rounded-lg border px-3 py-2 text-left text-sm ${
                                  chosen === undefined
                                    ? "border-zinc-700 hover:border-zinc-500"
                                    : isAnswer
                                      ? "border-green-600 bg-green-950/40 text-green-100"
                                      : isChosen
                                        ? "border-red-700 bg-red-950/40 text-red-200"
                                        : "border-zinc-800 text-zinc-500"
                                }`}
                              >
                                {opt}
                              </button>
                            );
                          })}
                        </div>
                        {chosen !== undefined && (
                          <p
                            className={`mt-3 text-sm ${
                              correct ? "text-green-300" : "text-red-300"
                            }`}
                          >
                            {correct ? "Correct. " : "Not quite. "}
                            {q.explanation}
                          </p>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="rounded-xl border border-amber-900/60 bg-amber-950/20 p-4">
                <h3 className="font-semibold text-amber-200">
                  Related real records (from the database)
                </h3>
                <p className="mt-1 text-xs text-zinc-400">
                  These are real vulnerability records linked to this
                  topic&apos;s CWE IDs. They are data, not lesson text — the
                  educational content above is separate.
                </p>
                {detail.topic.related_real_records.length === 0 ? (
                  <p className="mt-2 text-sm text-zinc-400">
                    No real records are linked to this topic yet in this
                    database.
                  </p>
                ) : (
                  <ul className="mt-3 flex flex-col gap-2">
                    {detail.topic.related_real_records.map((rec) => (
                      <li
                        key={rec.cve_id}
                        className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3 text-sm"
                      >
                        <span className="font-mono font-semibold">
                          {rec.cve_id}
                        </span>{" "}
                        <span className="text-zinc-400">
                          {rec.severity ?? "severity unknown"}
                          {rec.cvss_score !== null
                            ? ` · CVSS ${rec.cvss_score}`
                            : ""}
                          {rec.related_cwe_id ? ` · ${rec.related_cwe_id}` : ""}
                        </span>
                        <p className="mt-1 text-zinc-300">{rec.description}</p>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </article>
          ) : null}
        </section>
      </div>
    </div>
  );
}
