// Cloudflare Worker: serves public/ as static assets and /api/doc backed by D1 (binding: DB).
// Protection (optional): if the secret SITE_PASSWORD is set, HTTP Basic Auth guards EVERYTHING (any username).
// If it is NOT set, the site is OPEN — temporary mode; do not import real student data in this mode.
import { onRequest as docHandler } from "../functions/api/doc.js";

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function authorized(request, env) {
  const pass = env.SITE_PASSWORD;
  if (!pass) return false;
  const h = request.headers.get("authorization") || "";
  if (!h.startsWith("Basic ")) return false;
  let decoded = "";
  try { decoded = new TextDecoder().decode(Uint8Array.from(atob(h.slice(6)), c => c.charCodeAt(0))); } catch { return false; }
  const given = decoded.slice(decoded.indexOf(":") + 1);
  return timingSafeEqual(given, pass);
}

export default {
  async fetch(request, env, ctx) {
    if (env.SITE_PASSWORD && !authorized(request, env)) {
      return new Response("مطلوب تسجيل الدخول", {
        status: 401,
        headers: { "WWW-Authenticate": 'Basic realm="Smart Teacher Platform", charset="UTF-8"',
                   "content-type": "text/plain; charset=utf-8" } });
    }
    const url = new URL(request.url);
    if (url.pathname === "/api/doc") return docHandler({ request, env, ctx });
    return env.ASSETS.fetch(request);
  }
};
