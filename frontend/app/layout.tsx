import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import "./globals.css";
import QueryProvider from "@/components/QueryProvider";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "CyberMap AI — Vulnerability Intelligence",
  description:
    "Understand vulnerabilities. Connect threats. Think like a security researcher.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased dark`}
    >
      <body className="min-h-full bg-[#0b0f14] text-zinc-100">
        <QueryProvider>
          <header className="border-b border-zinc-800">
            <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
              <Link href="/" className="flex items-baseline gap-2">
                <span className="text-lg font-bold tracking-tight text-cyan-400">
                  CyberMap AI
                </span>
                <span className="hidden text-xs text-zinc-500 sm:inline">
                  Vulnerability Intelligence
                </span>
              </Link>
              <nav className="flex flex-wrap gap-4 text-sm text-zinc-400">
                <Link href="/dashboard" className="hover:text-zinc-100">
                  Dashboard
                </Link>
                <Link
                  href="/vulnerabilities"
                  className="hover:text-zinc-100"
                >
                  Vulnerabilities
                </Link>
                <Link
                  href="/intelligence"
                  className="hover:text-zinc-100"
                >
                  Intelligence
                </Link>
                <Link
                  href="/attack-graph"
                  className="hover:text-zinc-100"
                >
                  Attack Graph
                </Link>
                <Link
                  href="/ai-assistant"
                  className="hover:text-zinc-100"
                >
                  AI Assistant
                </Link>
                <Link href="/research" className="hover:text-zinc-100">
                  Research
                </Link>
                <Link href="/learning" className="hover:text-zinc-100">
                  Learning
                </Link>
                <Link href="/login" className="hover:text-zinc-100">
                  Log in
                </Link>
              </nav>
            </div>
          </header>
          <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
          <footer className="border-t border-zinc-800 py-6 text-center text-xs text-zinc-600">
            CyberMap AI — every statistic comes from the indexed
            database; missing data is shown as unavailable, never as
            zero risk.
          </footer>
        </QueryProvider>
      </body>
    </html>
  );
}
