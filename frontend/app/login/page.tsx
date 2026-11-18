"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import {
  fetchMe,
  login,
  LoginFormSchema,
} from "@/lib/services/auth";
import { ApiError } from "@/lib/services/client";

const inputClass =
  "w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-cyan-500 focus:outline-none";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Already logged in? Skip the form.
  useEffect(() => {
    let cancelled = false;
    fetchMe()
      .then((user) => {
        if (!cancelled && user) router.replace("/dashboard");
      })
      .catch(() => {
        /* not logged in — stay on the form */
      });
    return () => {
      cancelled = true;
    };
  }, [router]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setFieldError(null);
    const parsed = LoginFormSchema.safeParse({ username, password });
    if (!parsed.success) {
      setFieldError(parsed.error.issues[0]?.message ?? "Invalid input");
      return;
    }
    setBusy(true);
    try {
      await login(parsed.data);
      router.push("/dashboard");
      router.refresh();
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError(
          "Too many failed login attempts — try again in 15 minutes.",
        );
      } else if (err instanceof ApiError) {
        setError(
          err.status === 401
            ? "Invalid username or password."
            : err.message,
        );
      } else {
        setError("Could not reach the backend. Is it running?");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-md">
      <h1 className="text-2xl font-bold tracking-tight">Log in</h1>
      <p className="mt-1 text-sm text-zinc-400">
        Sign in to your CyberMap AI research workspace.
      </p>
      <form
        onSubmit={onSubmit}
        className="mt-6 flex flex-col gap-4 rounded-xl border border-zinc-800 bg-zinc-900/60 p-5"
      >
        <label className="flex flex-col gap-1 text-sm text-zinc-300">
          Username or email
          <input
            className={inputClass}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            placeholder="professor@example.com"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm text-zinc-300">
          Password
          <input
            className={inputClass}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            placeholder="Your password"
          />
        </label>
        {fieldError ? (
          <p className="text-sm text-amber-300">{fieldError}</p>
        ) : null}
        {error ? (
          <p className="rounded-lg border border-red-900 bg-red-950/40 px-3 py-2 text-sm text-red-200">
            {error}
          </p>
        ) : null}
        <button
          type="submit"
          disabled={busy}
          className="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
        >
          {busy ? "Logging in…" : "Log in"}
        </button>
      </form>
      <p className="mt-4 text-sm text-zinc-400">
        No account yet?{" "}
        <Link href="/register" className="text-cyan-400 underline">
          Register
        </Link>
      </p>
    </div>
  );
}
