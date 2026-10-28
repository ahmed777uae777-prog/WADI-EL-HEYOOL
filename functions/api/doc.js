// Cloudflare Pages Function: tiny document store backed by D1 (binding name: DB).
// GET /api/doc?path=school/teachers  -> JSON body or 404
// PUT /api/doc?path=school/teachers  -> stores the JSON body
const PATH_RE = /^[A-Za-z0-9_-]{1,40}\/[A-Za-z0-9_-]{1,40}$/;
const MAX_BYTES = 8 * 1024 * 1024;
const J = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

export async function onRequest({ request, env }) {
  const path = new URL(request.url).searchParams.get("path") || "";
  if (!PATH_RE.test(path)) return new Response(JSON.stringify({ error: "bad_path" }), { status: 400, headers: J });
  if (!env.DB) return new Response(JSON.stringify({ error: "d1_not_bound" }), { status: 500, headers: J });

  if (request.method === "GET") {
    const row = await env.DB.prepare("SELECT body FROM docs WHERE path = ?").bind(path).first();
    if (!row) return new Response(JSON.stringify({ error: "not_found" }), { status: 404, headers: J });
    return new Response(row.body, { headers: J });
  }
  if (request.method === "PUT") {
    const text = await request.text();
    if (text.length > MAX_BYTES) return new Response(JSON.stringify({ error: "too_large" }), { status: 413, headers: J });
    try { JSON.parse(text); } catch { return new Response(JSON.stringify({ error: "bad_json" }), { status: 400, headers: J }); }
    await env.DB.prepare(
      "INSERT INTO docs (path, body, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(path) DO UPDATE SET body = ?2, updated_at = ?3"
    ).bind(path, text, Date.now()).run();
    return new Response(JSON.stringify({ ok: true }), { headers: J });
  }
  return new Response(JSON.stringify({ error: "method_not_allowed" }), { status: 405, headers: J });
}
