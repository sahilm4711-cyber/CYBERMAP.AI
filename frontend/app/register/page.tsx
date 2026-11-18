"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import {
  login,
  register,
  RegisterFormSchema,
} from "@/lib/services/auth";
import { ApiError } from "@/lib/services/client";

const inputClass =
  "w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-cyan-500 focus:outline-none";

export default function RegisterPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setFieldError(null);
    const parsed = RegisterFormSchema.safeParse({
      username,
      email,
      password,
      confirmPassword,
    });
    if (!parsed.success) {
      setFieldError(parsed.error.issues[0]?.message ?? "Invalid input");
      return;
    }
    setBusy(true);
    try {
      await register({
        username: parsed.data.username,
        email: parsed.data.email,
        password: parsed.data.password,
      });
      // Registration does not set a session cookie, so log in with
      // the same credentials and then go to the dashboard.
      await login({
        username: parsed.data.username,
        password: parsed.data.password,
      });
      router.push("/dashboard");
      router.refresh();
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setError("That username or email is already registered.");
      } else if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Could not reach the backend. Is it running?");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-md">
      <h1 className="text-2xl font-bold tracking-tight">
        Create an account
      </h1>
      <p className="mt-1 text-sm text-zinc-400">
        Research accounts are free. Use a password of at least 8
        characters — common passwords are rejected.
      </p>
      <form
        onSubmit={onSubmit}
        className="mt-6 flex flex-col gap-4 rounded-xl border border-zinc-800 bg-zinc-900/60 p-5"
      >
        <label className="flex flex-col gap-1 text-sm text-zinc-300">
          Username
          <input
            className={inputClass}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            placeholder="professor"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm text-zinc-300">
          Email
          <input
            className={inputClass}
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            placeholder="you@example.com"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm text-zinc-300">
          Password
          <input
            className={inputClass}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            placeholder="At least 8 characters"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm text-zinc-300">
          Confirm password
          <input
            className={inputClass}
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            autoComplete="new-password"
            placeholder="Repeat your password"
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
          {busy ? "Creating account…" : "Register"}
        </button>
      </form>
      <p className="mt-4 text-sm text-zinc-400">
        Already have an account?{" "}
        <Link href="/login" className="text-cyan-400 underline">
          Log in
        </Link>
      </p>
    </div>
  );
}
