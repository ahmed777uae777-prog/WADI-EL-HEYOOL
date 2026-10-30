// Cloudflare Worker for منصة المعلّم الذكية.
// - Serves public/ as static assets.
// - /api/public  : school name + whether an admin exists (no secrets) — for the login screen.
// - /api/setup   : first-run creation of the admin account (only while none exists).
// - /api/login   : verifies username/password ON THE SERVER, opens a session (HttpOnly cookie).
// - /api/logout, /api/me
// - /api/doc     : the shared data store (D1). Requires a session. Passwords are stored hashed
//                  and are NEVER returned; teachers can only write the documents they need.
// Optional: if the secret SITE_PASSWORD is set, HTTP Basic Auth additionally guards everything.

const J = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const json = (obj, status = 200, extra = {}) => new Response(JSON.stringify(obj), { status, headers: { ...J, ...extra } });
const PATH_RE = /^[A-Za-z0-9_-]{1,40}\/[A-Za-z0-9_-]{1,40}$/;
const MAX_BYTES = 8 * 1024 * 1024;
const SESSION_DAYS = 30;
const TEACHER_WRITABLE = new Set(["school/absences", "school/substitutes", "school/studentabsences", "school/lrcBookings", "school/auditlog"]);

/* ---------------- storage helpers ---------------- */
let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS docs (path TEXT PRIMARY KEY, body TEXT NOT NULL, updated_at INTEGER NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, data TEXT NOT NULL, expires INTEGER NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS sys (k TEXT PRIMARY KEY, v TEXT NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS login_fail (k TEXT PRIMARY KEY, n INTEGER NOT NULL, until INTEGER NOT NULL)"),
  ]);
  schemaReady = true;
}
async function getDoc(db, path) {
  const row = await db.prepare("SELECT body FROM docs WHERE path = ?").bind(path).first();
  if (!row) return null;
  try { return JSON.parse(row.body); } catch { return null; }
}
async function putDoc(db, path, obj) {
  await db.prepare("INSERT INTO docs (path, body, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(path) DO UPDATE SET body = ?2, updated_at = ?3")
    .bind(path, JSON.stringify(obj), Date.now()).run();
}

/* ---------------- password hashing ----------------
   HMAC-SHA256(pepper, salt + password). The pepper is a random server-side secret kept in the
   `sys` table (never served by /api/doc). Fast enough for the Workers CPU budget even when an
   admin saves the whole staff list at once. */
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const randHex = (n) => { const a = new Uint8Array(n); crypto.getRandomValues(a); return hex(a); };
let pepperKey = null;
async function getPepperKey(db) {
  if (pepperKey) return pepperKey;
  let row = await db.prepare("SELECT v FROM sys WHERE k = 'pepper'").first();
  if (!row) {
    await db.prepare("INSERT OR IGNORE INTO sys (k, v) VALUES ('pepper', ?)").bind(randHex(32)).run();
    row = await db.prepare("SELECT v FROM sys WHERE k = 'pepper'").first();
  }
  pepperKey = await crypto.subtle.importKey("raw", enc.encode(row.v), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return pepperKey;
}
const isHashed = (s) => typeof s === "string" && s.startsWith("h1$");
async function hashPassword(db, password) {
  const salt = randHex(16);
  const mac = await crypto.subtle.sign("HMAC", await getPepperKey(db), enc.encode(salt + ":" + password));
  return `h1$${salt}$${hex(mac)}`;
}
async function verifyPassword(db, password, stored) {
  if (!stored) return false;
  if (!isHashed(stored)) return timingSafeEqual(String(password), String(stored)); // legacy plaintext (migrated on login)
  const [, salt, h] = stored.split("$");
  const mac = hex(await crypto.subtle.sign("HMAC", await getPepperKey(db), enc.encode(salt + ":" + password)));
  return timingSafeEqual(mac, h);
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

/* ---------------- sessions ---------------- */
function cookieToken(request) {
  const m = (request.headers.get("cookie") || "").match(/(?:^|;\s*)sid=([a-f0-9]{64})/);
  return m ? m[1] : null;
}
function sessionCookie(token, remember) {
  const base = `sid=${token}; Path=/; HttpOnly; Secure; SameSite=Lax`;
  return remember ? `${base}; Max-Age=${SESSION_DAYS * 86400}` : base;
}
async function createSession(db, user, remember) {
  const token = randHex(32);
  const ttl = remember ? SESSION_DAYS * 86400e3 : 86400e3;
  await db.prepare("INSERT INTO sessions (token, data, expires) VALUES (?, ?, ?)").bind(token, JSON.stringify(user), Date.now() + ttl).run();
  await db.prepare("DELETE FROM sessions WHERE expires < ?").bind(Date.now()).run();
  return token;
}
// Returns the session user, re-checked against the live staff list (disabled / deleted /
// demoted accounts lose access immediately), or null.
async function currentUser(db, request) {
  const token = cookieToken(request);
  if (!token) return null;
  const row = await db.prepare("SELECT data, expires FROM sessions WHERE token = ?").bind(token).first();
  if (!row || row.expires < Date.now()) return null;
  let user; try { user = JSON.parse(row.data); } catch { return null; }
  if (user.teacherId) {
    const list = (await getDoc(db, "school/teachers"))?.list || [];
    const t = list.find((x) => x.id === user.teacherId);
    if (!t || t.active === false) { await db.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run(); return null; }
    if (user.role === "admin" && !t.isAdmin) user = { role: "teacher", name: t.name, subject: t.subject, teacherId: t.id, title: t.title || "" };
    user.name = t.name;
  }
  user.token = token;
  return user;
}

/* ---------------- login rate limiting ---------------- */
async function isLocked(db, key) {
  const r = await db.prepare("SELECT n, until FROM login_fail WHERE k = ?").bind(key).first();
  return !!(r && r.until > Date.now() && r.n >= 5);
}
async function noteFail(db, key) {
  const r = await db.prepare("SELECT n, until FROM login_fail WHERE k = ?").bind(key).first();
  const now = Date.now();
  const n = r && r.until > now ? r.n + 1 : 1;
  await db.prepare("INSERT INTO login_fail (k, n, until) VALUES (?1, ?2, ?3) ON CONFLICT(k) DO UPDATE SET n = ?2, until = ?3")
    .bind(key, n, now + 15 * 60e3).run();
}
async function clearFails(db, key) { await db.prepare("DELETE FROM login_fail WHERE k = ?").bind(key).run(); }

/* ---------------- what clients may see / write ---------------- */
function publicTeachers(list) {
  return (list || []).map((t) => { const { code, ...rest } = t; return { ...rest, code: "", hasCode: !!code }; });
}
function publicInfo(info) {
  if (!info) return info;
  const { adminCode, ...rest } = info;
  return { ...rest, hasAdminCode: !!adminCode };
}
// Merge an incoming staff list from the admin UI with the stored one: a new plaintext password
// is hashed; an empty one keeps the stored hash when the client says the account has one.
async function mergeTeachers(db, incoming) {
  const stored = (await getDoc(db, "school/teachers"))?.list || [];
  const byId = new Map(stored.map((t) => [t.id, t]));
  const out = [];
  for (const t of incoming.list || []) {
    const prev = byId.get(t.id);
    const { hasCode, ...rec } = t;
    if (typeof rec.code === "string" && rec.code && !isHashed(rec.code)) rec.code = await hashPassword(db, rec.code);
    else if (isHashed(rec.code)) rec.code = prev && prev.code === rec.code ? rec.code : (prev?.code || "");
    else rec.code = hasCode && prev?.code ? prev.code : "";
    out.push(rec);
  }
  return { ...incoming, list: out };
}
async function mergeInfo(db, incoming) {
  const stored = (await getDoc(db, "school/info")) || {};
  const { hasAdminCode, ...rec } = incoming;
  if (typeof rec.adminCode === "string" && rec.adminCode && !isHashed(rec.adminCode)) rec.adminCode = await hashPassword(db, rec.adminCode);
  else rec.adminCode = stored.adminCode || "";
  if (!rec.adminUsername && stored.adminUsername) rec.adminUsername = stored.adminUsername;
  return rec;
}

/* ---------------- handlers ---------------- */
async function handleLogin(db, request) {
  const body = await request.json().catch(() => ({}));
  const username = String(body.username || "").trim(), password = String(body.password || "");
  const mode = ["admin", "teacher", "any"].includes(body.mode) ? body.mode : "any";
  if (!username || !password) return json({ error: "missing" }, 400);
  const ip = request.headers.get("cf-connecting-ip") || "ip";
  const uKey = "u:" + username.toLowerCase(), ipKey = "ip:" + ip;
  if (await isLocked(db, uKey) || await isLocked(db, ipKey)) return json({ error: "locked" }, 429);

  const info = (await getDoc(db, "school/info")) || {};
  const teachersDoc = (await getDoc(db, "school/teachers")) || { list: [] };
  const ul = username.toLowerCase();
  let user = null;

  if (mode !== "teacher" && info.adminUsername && ul === String(info.adminUsername).toLowerCase() && await verifyPassword(db, password, info.adminCode)) {
    user = { role: "admin", name: "مدير المدرسة", main: true };
    if (!isHashed(info.adminCode)) { info.adminCode = await hashPassword(db, password); await putDoc(db, "school/info", info); }
  }
  if (!user) {
    const t = (teachersDoc.list || []).find((x) => x.username && String(x.username).toLowerCase() === ul);
    if (t && (mode !== "admin" || t.isAdmin)) {
      if (t.active === false) return json({ error: "disabled" }, 403);
      if (!t.code) return json({ error: "not_activated" }, 403);
      if (await verifyPassword(db, password, t.code)) {
        user = t.isAdmin && mode === "admin"
          ? { role: "admin", name: t.name, teacherId: t.id, coAdmin: true, title: t.title || "" }
          : { role: "teacher", name: t.name, subject: t.subject, teacherId: t.id, title: t.title || "" };
        if (!isHashed(t.code)) { t.code = await hashPassword(db, password); await putDoc(db, "school/teachers", teachersDoc); }
      }
    }
  }
  if (!user) { await noteFail(db, uKey); await noteFail(db, ipKey); return json({ error: "invalid" }, 401); }
  await clearFails(db, uKey);
  const remember = body.remember !== false;
  const token = await createSession(db, user, remember);
  return json({ ok: true, user }, 200, { "set-cookie": sessionCookie(token, remember) });
}

async function handleSetup(db, request) {
  const body = await request.json().catch(() => ({}));
  const username = String(body.username || "").trim(), password = String(body.password || "");
  if (!username || password.length < 4) return json({ error: "invalid" }, 400);
  const info = (await getDoc(db, "school/info")) || { name: "مدرسة وادي الحيول (١-١٢)" };
  if (info.adminUsername) return json({ error: "exists" }, 409);
  info.adminUsername = username;
  info.adminCode = await hashPassword(db, password);
  await putDoc(db, "school/info", info);
  return json({ ok: true });
}

async function handleDoc(db, request, user) {
  const path = new URL(request.url).searchParams.get("path") || "";
  if (!PATH_RE.test(path)) return json({ error: "bad_path" }, 400);
  if (!user) return json({ error: "unauthorized" }, 401);
  const isAdmin = user.role === "admin";

  if (request.method === "GET") {
    const doc = await getDoc(db, path);
    if (!doc) return json({ error: "not_found" }, 404);
    if (path === "school/teachers") return json({ ...doc, list: publicTeachers(doc.list) });
    if (path === "school/info") return json(publicInfo(doc));
    return json(doc);
  }
  if (request.method === "PUT") {
    if (!isAdmin && !TEACHER_WRITABLE.has(path) && !path.startsWith("classroom/")) return json({ error: "forbidden" }, 403);
    const text = await request.text();
    if (text.length > MAX_BYTES) return json({ error: "too_large" }, 413);
    let obj; try { obj = JSON.parse(text); } catch { return json({ error: "bad_json" }, 400); }
    if (path === "school/teachers") obj = await mergeTeachers(db, obj);
    if (path === "school/info") obj = await mergeInfo(db, obj);
    await putDoc(db, path, obj);
    return json({ ok: true });
  }
  return json({ error: "method_not_allowed" }, 405);
}

/* ---------------- optional site-wide Basic Auth ---------------- */
function basicAuthorized(request, env) {
  const h = request.headers.get("authorization") || "";
  if (!h.startsWith("Basic ")) return false;
  let decoded = "";
  try { decoded = new TextDecoder().decode(Uint8Array.from(atob(h.slice(6)), (c) => c.charCodeAt(0))); } catch { return false; }
  return timingSafeEqual(decoded.slice(decoded.indexOf(":") + 1), env.SITE_PASSWORD);
}

export default {
  async fetch(request, env) {
    if (env.SITE_PASSWORD && !basicAuthorized(request, env)) {
      return new Response("مطلوب تسجيل الدخول", { status: 401, headers: { "WWW-Authenticate": 'Basic realm="Smart Teacher Platform", charset="UTF-8"', "content-type": "text/plain; charset=utf-8" } });
    }
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      if (!env.DB) return json({ error: "d1_not_bound" }, 500);
      const db = env.DB;
      await ensureSchema(db);
      // State-changing API calls must come from this site (blocks cross-site form posts).
      if (request.method !== "GET") {
        const origin = request.headers.get("origin");
        if (origin && origin !== url.origin) return json({ error: "bad_origin" }, 403);
      }
      try {
        switch (url.pathname) {
          case "/api/public": {
            const info = (await getDoc(db, "school/info")) || {};
            return json({ name: info.name || "", hasAdmin: !!info.adminUsername });
          }
          case "/api/setup": return request.method === "POST" ? handleSetup(db, request) : json({ error: "method_not_allowed" }, 405);
          case "/api/login": return request.method === "POST" ? handleLogin(db, request) : json({ error: "method_not_allowed" }, 405);
          case "/api/logout": {
            const token = cookieToken(request);
            if (token) await db.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
            return json({ ok: true }, 200, { "set-cookie": "sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0" });
          }
          case "/api/me": {
            const user = await currentUser(db, request);
            if (!user) return json({ user: null });
            const { token, ...u } = user;
            return json({ user: u });
          }
          case "/api/doc": return handleDoc(db, request, await currentUser(db, request));
          default: return json({ error: "not_found" }, 404);
        }
      } catch (err) {
        return json({ error: "server_error" }, 500);
      }
    }
    if (/^\/admin\/?$/i.test(url.pathname)) return env.ASSETS.fetch(new Request(new URL("/", url), request));
    return env.ASSETS.fetch(request);
  },
};
