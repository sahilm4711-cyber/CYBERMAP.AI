import { z } from "zod";
import { apiBaseUrl } from "@/lib/api";
import { ApiError } from "@/lib/services/client";

export const UserSchema = z.object({
  id: z.string(),
  username: z.string(),
  email: z.string(),
  role: z.string(),
  is_active: z.boolean(),
  created_at: z.string().nullable(),
  last_login_at: z.string().nullable(),
});
export type AuthUser = z.infer<typeof UserSchema>;

/** Client-side validation mirrors the backend (min length 8). */
export const RegisterFormSchema = z
  .object({
    username: z
      .string()
      .min(3, "Username must be at least 3 characters")
      .max(64),
    email: z.string().email("Enter a valid email address"),
    password: z
      .string()
      .min(8, "Password must be at least 8 characters"),
    confirmPassword: z.string(),
  })
  .refine((v) => v.password === v.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"],
  });

export const LoginFormSchema = z.object({
  username: z.string().min(1, "Enter your username or email"),
  password: z.string().min(1, "Enter your password"),
});

const BASE = "/api/v1/auth";

async function request<T>(
  path: string,
  schema: z.ZodType<T>,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(`${apiBaseUrl()}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) {
        detail = body.detail
          .map((d: { msg?: string }) => d.msg ?? "Invalid input")
          .join("; ");
      }
    } catch {
      /* keep default detail */
    }
    throw new ApiError(res.status, `${res.status}: ${detail}`);
  }
  return schema.parse(await res.json());
}

export async function login(input: {
  username: string;
  password: string;
}): Promise<AuthUser> {
  return request(`${BASE}/login`, UserSchema, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function register(input: {
  username: string;
  email: string;
  password: string;
}): Promise<AuthUser> {
  return request(`${BASE}/register`, UserSchema, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export async function logout(): Promise<void> {
  const res = await fetch(`${apiBaseUrl()}${BASE}/logout`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) {
    throw new ApiError(res.status, `Logout failed (${res.status})`);
  }
}

export async function fetchMe(): Promise<AuthUser | null> {
  try {
    return await request(`${BASE}/me`, UserSchema);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) return null;
    throw err;
  }
}
