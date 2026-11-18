# CyberMap AI — Frontend

Next.js 16 (App Router) + TypeScript + React 19 + Tailwind CSS 4.

See the root `README.md` for the full project setup. Quick start:

```bash
npm install
npm run dev        # http://localhost:3000
```

The frontend talks to the FastAPI backend at `NEXT_PUBLIC_API_URL`
(default `http://localhost:8000`, see `.env.example`).

Key files:

- `app/` — App Router pages (home page shows live backend health)
- `components/` — `HealthStatus`, `HealthSection`, `QueryProvider`
- `lib/api.ts` — typed API client (Zod-validated health response)
