import { runHttpProbe } from "../../../packages/monitoring-core/src/http-probe";

interface Env {
  DB: D1Database;
  APP_ENV: string;
  PUBLIC_APP_URL: string;
}

const json = (data: unknown, status = 200): Response =>
  Response.json(data, { status, headers: { "cache-control": "no-store" } });

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ service: "zetuwatch-api", status: "ok", environment: env.APP_ENV });
    }

    if (request.method === "POST" && url.pathname === "/v1/probe-preview") {
      let body: { url?: string; method?: string; expectedStatus?: number };
      try { body = await request.json(); } catch { return json({ error: "INVALID_JSON" }, 400); }
      if (!body.url) return json({ error: "URL_REQUIRED" }, 400);
      try {
        const result = await runHttpProbe(body.url, body.method ?? "GET", body.expectedStatus ?? 200);
        return json({ ...result, note: "Unauthenticated preview only. Do not use as a public relay." });
      } catch (error) {
        return json({ error: error instanceof Error ? error.message : "INVALID_REQUEST" }, 400);
      }
    }

    return json({ error: "NOT_FOUND" }, 404);
  }
};
