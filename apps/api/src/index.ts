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

    return json({ error: "NOT_FOUND" }, 404);
  }
};
