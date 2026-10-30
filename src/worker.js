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
    db.prepare("CREATE TABLE IF NOT EXISTS ai_usage (k TEXT PRIMARY KEY, n INTEGER NOT NULL, until INTEGER NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS portfolio (id TEXT PRIMARY KEY, teacher_id TEXT NOT NULL, data TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS file_meta (id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL, size INTEGER NOT NULL, chunks INTEGER NOT NULL, created INTEGER NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS file_chunks (id TEXT NOT NULL, idx INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (id, idx))"),
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
// Admins need to read teachers' passwords back (to hand them out / export them), so besides the
// one-way hash a copy is kept encrypted with AES-GCM under a server-only key; it is decrypted
// only for admin sessions via /api/credentials and never appears in /api/doc responses.
let encKey = null;
async function getEncKey(db) {
  if (encKey) return encKey;
  let row = await db.prepare("SELECT v FROM sys WHERE k = 'enc'").first();
  if (!row) {
    await db.prepare("INSERT OR IGNORE INTO sys (k, v) VALUES ('enc', ?)").bind(randHex(32)).run();
    row = await db.prepare("SELECT v FROM sys WHERE k = 'enc'").first();
  }
  const raw = new Uint8Array(row.v.match(/../g).map((h) => parseInt(h, 16)));
  encKey = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  return encKey;
}
async function encryptCode(db, text) {
  const iv = new Uint8Array(12); crypto.getRandomValues(iv);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await getEncKey(db), enc.encode(text));
  return hex(iv) + "." + hex(ct);
}
async function decryptCode(db, blob) {
  try {
    const [ivh, cth] = String(blob || "").split(".");
    const toBytes = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: toBytes(ivh) }, await getEncKey(db), toBytes(cth));
    return new TextDecoder().decode(pt);
  } catch { return ""; }
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
  return (list || []).map((t) => { const { code, codeEnc, ...rest } = t; return { ...rest, code: "", hasCode: !!code }; });
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
    const { hasCode, codeEnc, ...rec } = t;
    if (typeof rec.code === "string" && rec.code && !isHashed(rec.code)) { rec.codeEnc = await encryptCode(db, rec.code); rec.code = await hashPassword(db, rec.code); }
    else if (hasCode && prev?.code) { rec.code = prev.code; if (prev.codeEnc) rec.codeEnc = prev.codeEnc; }
    else rec.code = "";
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
        if (!isHashed(t.code) || !t.codeEnc) { t.codeEnc = await encryptCode(db, password); t.code = await hashPassword(db, password); await putDoc(db, "school/teachers", teachersDoc); }
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


/* ---------------- المبادرات والإنجازات (portfolio) + evidence files ----------------
   Entries live in their own table so the server can enforce ownership: a teacher reads/edits
   only their own entries (and only until they are evaluated); admins read everything and
   evaluate. Files are stored in D1 in 1.5 MB chunks and served only to the owner or admins. */
const FILE_MAX = 20 * 1024 * 1024, CHUNK = 1536 * 1024;
const PF_TYPES = ["مبادرة", "إنجاز", "مشاركة أو مسابقة", "ورشة أو تدريب قدّمته", "تدريب حضرته", "درس تطبيقي أو بحث إجرائي", "خدمة مجتمع", "عمل آخر"];
const clip = (v, n) => String(v == null ? "" : v).slice(0, n);
function cleanLinks(arr) {
  return (Array.isArray(arr) ? arr : []).map((u) => clip(u, 600).trim()).filter((u) => /^https?:\/\/\S+$/i.test(u)).slice(0, 15);
}
async function handleFiles(db, request, user, url) {
  if (!user) return json({ error: "unauthorized" }, 401);
  const id = url.pathname.split("/")[3] || "";
  if (request.method === "POST" && !id) {
    if (!user.teacherId && user.role !== "admin") return json({ error: "forbidden" }, 403);
    const buf = await request.arrayBuffer();
    if (!buf.byteLength) return json({ error: "empty" }, 400);
    if (buf.byteLength > FILE_MAX) return json({ error: "too_large" }, 413);
    const fid = "f" + randHex(12);
    const name = clip(decodeURIComponent(url.searchParams.get("name") || "ملف"), 200);
    const type = clip(request.headers.get("content-type") || "application/octet-stream", 120);
    if (/^video\//i.test(type) || /\.(mp4|mov|avi|mkv|wmv|webm|m4v|3gp|flv)$/i.test(name)) return json({ error: "video_not_allowed" }, 415);
    const chunks = Math.ceil(buf.byteLength / CHUNK);
    const stmts = [];
    for (let i = 0; i < chunks; i++) stmts.push(db.prepare("INSERT INTO file_chunks (id, idx, data) VALUES (?, ?, ?)").bind(fid, i, buf.slice(i * CHUNK, (i + 1) * CHUNK)));
    stmts.push(db.prepare("INSERT INTO file_meta (id, owner, name, type, size, chunks, created) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(fid, user.teacherId || "admin", name, type, buf.byteLength, chunks, Date.now()));
    await db.batch(stmts);
    return json({ ok: true, file: { id: fid, name, type, size: buf.byteLength } });
  }
  if (request.method === "GET" && id) {
    const meta = await db.prepare("SELECT * FROM file_meta WHERE id = ?").bind(id).first();
    if (!meta) return json({ error: "not_found" }, 404);
    if (user.role !== "admin" && meta.owner !== user.teacherId) return json({ error: "forbidden" }, 403);
    const rows = (await db.prepare("SELECT data FROM file_chunks WHERE id = ? ORDER BY idx").bind(id).all()).results || [];
    const parts = rows.map((r) => new Uint8Array(r.data));
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
    // Only passive media and PDF may open in the browser; anything else (html, svg, scripts…)
    // is forced to download so an uploaded file can never run code on this site.
    const safeInline = /^(image\/(png|jpe?g|gif|webp|bmp)|application\/pdf)/i.test(meta.type);
    const dl = url.searchParams.get("download") === "1" || !safeInline;
    return new Response(out, { headers: { "content-type": safeInline ? meta.type : "application/octet-stream", "cache-control": "private, no-store",
      "content-disposition": `${dl ? "attachment" : "inline"}; filename*=UTF-8''${encodeURIComponent(meta.name)}`, "x-content-type-options": "nosniff" } });
  }
  return json({ error: "method_not_allowed" }, 405);
}
async function deleteFiles(db, ids) {
  for (const id of ids || []) {
    await db.batch([db.prepare("DELETE FROM file_chunks WHERE id = ?").bind(id), db.prepare("DELETE FROM file_meta WHERE id = ?").bind(id)]);
  }
}
async function handlePortfolio(db, request, user, url) {
  if (!user) return json({ error: "unauthorized" }, 401);
  const isAdmin = user.role === "admin";
  const id = url.searchParams.get("id") || "";
  const rowToEntry = (r) => ({ ...JSON.parse(r.data), id: r.id, teacherId: r.teacher_id, created: r.created, updated: r.updated });
  if (request.method === "GET") {
    const rows = isAdmin
      ? (await db.prepare("SELECT * FROM portfolio ORDER BY created DESC").all()).results
      : (await db.prepare("SELECT * FROM portfolio WHERE teacher_id = ? ORDER BY created DESC").bind(user.teacherId || "-").all()).results;
    return json({ list: (rows || []).map(rowToEntry), types: PF_TYPES });
  }
  const body = request.method === "DELETE" ? {} : await request.json().catch(() => ({}));
  const ownFiles = async (files) => {
    const list = (Array.isArray(files) ? files : []).slice(0, 20);
    const ok = [];
    for (const f of list) {
      const m = await db.prepare("SELECT id, name, type, size, owner FROM file_meta WHERE id = ?").bind(String(f.id || "")).first();
      if (m && (m.owner === user.teacherId || isAdmin)) ok.push({ id: m.id, name: m.name, type: m.type, size: m.size });
    }
    return ok;
  };
  const fields = async (b) => ({
    title: clip(b.title, 200).trim(), type: PF_TYPES.includes(b.type) ? b.type : "عمل آخر", date: clip(b.date, 10),
    domain: clip(b.domain, 120).trim(), description: clip(b.description, 6000).trim(), beneficiaries: clip(b.beneficiaries, 300).trim(),
    links: cleanLinks(b.links), files: await ownFiles(b.files),
  });
  if (request.method === "POST") {
    if (!user.teacherId) return json({ error: "forbidden" }, 403);
    const f = await fields(body);
    if (!f.title) return json({ error: "title_required" }, 400);
    const teachers = (await getDoc(db, "school/teachers"))?.list || [];
    const t = teachers.find((x) => x.id === user.teacherId);
    const entry = { ...f, teacherName: t ? t.name : user.name, subject: t ? (t.title || t.subject || "") : "", status: "pending", evaluation: null };
    const eid = "pf" + randHex(8), now = Date.now();
    await db.prepare("INSERT INTO portfolio (id, teacher_id, data, created, updated) VALUES (?, ?, ?, ?, ?)").bind(eid, user.teacherId, JSON.stringify(entry), now, now).run();
    return json({ ok: true, id: eid });
  }
  const row = id ? await db.prepare("SELECT * FROM portfolio WHERE id = ?").bind(id).first() : null;
  if (!row) return json({ error: "not_found" }, 404);
  const cur = JSON.parse(row.data);
  const mine = row.teacher_id === user.teacherId;
  if (request.method === "PUT") {
    let next;
    if (body.evaluate) {
      if (!isAdmin) return json({ error: "forbidden" }, 403);
      const RATINGS = ["ممتاز", "جيد جدًا", "جيد", "مقبول"];
      const status = body.status === "needs_info" ? "needs_info" : "evaluated";
      next = { ...cur, status, evaluation: { rating: status === "evaluated" && RATINGS.includes(body.rating) ? body.rating : "", note: clip(body.note, 2000).trim(), by: user.name, at: new Date().toISOString() } };
    } else {
      if (!mine) return json({ error: "forbidden" }, 403);
      if (cur.status === "evaluated") return json({ error: "locked" }, 409);
      const f = await fields(body);
      if (!f.title) return json({ error: "title_required" }, 400);
      const removed = (cur.files || []).filter((x) => !f.files.some((y) => y.id === x.id)).map((x) => x.id);
      await deleteFiles(db, removed);
      next = { ...cur, ...f, status: "pending" };
    }
    await db.prepare("UPDATE portfolio SET data = ?, updated = ? WHERE id = ?").bind(JSON.stringify(next), Date.now(), id).run();
    return json({ ok: true });
  }
  if (request.method === "DELETE") {
    if (!isAdmin && !(mine && cur.status !== "evaluated")) return json({ error: "forbidden" }, 403);
    await deleteFiles(db, (cur.files || []).map((x) => x.id));
    await db.prepare("DELETE FROM portfolio WHERE id = ?").bind(id).run();
    return json({ ok: true });
  }
  return json({ error: "method_not_allowed" }, 405);
}


/* ---------------- AI (Cloudflare Workers AI) ----------------
   Replaces the claude.ai-only "sample" capability. Signed-in users only, with a per-user hourly cap. */
const AI_MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const AI_FALLBACK = "@cf/meta/llama-3.1-8b-instruct-fast";
const AI_PER_HOUR = 40;
async function handleAI(db, env, request, user) {
  if (request.method === "GET") return json({ available: !!env.AI });
  if (!user) return json({ error: "session_expired" }, 401);
  if (!env.AI) return json({ error: "capability_disabled" }, 503);
  const key = "ai:" + (user.teacherId || user.role), now = Date.now();
  const u = await db.prepare("SELECT n, until FROM ai_usage WHERE k = ?").bind(key).first();
  const n = u && u.until > now ? u.n + 1 : 1;
  if (n > AI_PER_HOUR) return json({ error: "rate_limited" }, 429);
  await db.prepare("INSERT INTO ai_usage (k, n, until) VALUES (?1, ?2, ?3) ON CONFLICT(k) DO UPDATE SET n = ?2, until = ?3")
    .bind(key, n, u && u.until > now ? u.until : now + 3600e3).run();
  const body = await request.json().catch(() => ({}));
  const prompt = clip(body.prompt, 24000);
  if (!prompt.trim()) return json({ error: "empty_completion" }, 400);
  const tier = body.tier === "quick" ? "quick" : "default";
  const system = (body.json
    ? "You are a helpful assistant for teachers in an Omani school. Reply with valid JSON only — no prose, no code fences."
    : "You are a helpful assistant for teachers and school administrators in Oman. Answer in clear Modern Standard Arabic unless asked otherwise. Follow the requested output format exactly.");
  try {
    const input = { messages: [{ role: "system", content: system }, { role: "user", content: prompt }],
      max_tokens: tier === "quick" ? 900 : 4000, temperature: body.json ? 0.4 : 0.7 };
    let out;
    try { out = await env.AI.run(AI_MODEL, input); }
    catch (e1) { out = await env.AI.run(AI_FALLBACK, { ...input, max_tokens: Math.min(input.max_tokens, 3000) }); }
    const text = (out && (out.response ?? out.result?.response)) || "";
    if (!String(text).trim()) return json({ error: "empty_completion" }, 502);
    return json({ text: typeof text === "string" ? text : JSON.stringify(text) });
  } catch (err) {
    const m = String(err && err.message || err);
    return json({ error: /limit|quota|429|neurons/i.test(m) ? "rate_limited" : "upstream_error" }, 502);
  }
}

/* ---------------- lesson media: AI images + YouTube videos ---------------- */
const IMG_MODEL = "@cf/black-forest-labs/flux-1-schnell";
async function bumpUsage(db, key, limit) {
  const now = Date.now();
  const u = await db.prepare("SELECT n, until FROM ai_usage WHERE k = ?").bind(key).first();
  const n = u && u.until > now ? u.n + 1 : 1;
  if (n > limit) return false;
  await db.prepare("INSERT INTO ai_usage (k, n, until) VALUES (?1, ?2, ?3) ON CONFLICT(k) DO UPDATE SET n = ?2, until = ?3")
    .bind(key, n, u && u.until > now ? u.until : now + 3600e3).run();
  return true;
}
async function handleImage(db, env, request, user) {
  if (!user) return json({ error: "session_expired" }, 401);
  if (!env.AI) return json({ error: "capability_disabled" }, 503);
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  if (!(await bumpUsage(db, "img:" + (user.teacherId || user.role), 30))) return json({ error: "rate_limited" }, 429);
  const body = await request.json().catch(() => ({}));
  const prompt = clip(body.prompt, 600).trim();
  if (!prompt) return json({ error: "empty_prompt" }, 400);
  try {
    const out = await env.AI.run(IMG_MODEL, { prompt: prompt + ", clean educational illustration for school students, bright colors, no text, no letters", steps: 4 });
    if (!out || !out.image) return json({ error: "upstream_error" }, 502);
    return json({ image: "data:image/jpeg;base64," + out.image });
  } catch (err) {
    const m = String(err && err.message || err);
    return json({ error: /limit|quota|429|neurons/i.test(m) ? "rate_limited" : "upstream_error" }, 502);
  }
}
async function handleVideos(db, request, user, url) {
  if (!user) return json({ error: "session_expired" }, 401);
  const q = clip(url.searchParams.get("q"), 200).trim();
  if (!q) return json({ list: [] });
  if (!(await bumpUsage(db, "vid:" + (user.teacherId || user.role), 60))) return json({ error: "rate_limited" }, 429);
  try {
    const r = await fetch("https://www.youtube.com/results?hl=ar&gl=OM&search_query=" + encodeURIComponent(q), {
      headers: { "accept-language": "ar,en;q=0.8", "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36", "cookie": "CONSENT=YES+1; SOCS=CAI" } });
    const html = await r.text();
    const list = [], seen = new Set();
    const re = /"videoRenderer":\{"videoId":"([\w-]{11})"[\s\S]{0,1500}?"title":\{"runs":\[\{"text":"((?:[^"\\]|\\.)*)"/g;
    let m;
    while ((m = re.exec(html)) && list.length < 4) {
      if (seen.has(m[1])) continue; seen.add(m[1]);
      let title = m[2]; try { title = JSON.parse('"' + m[2] + '"'); } catch {}
      list.push({ id: m[1], title });
    }
    return json({ list });
  } catch { return json({ list: [] }); }
}

/* ---------------- AR scene builder: writes three.js scene code like a human developer ---------------- */
const AR_PER_HOUR = 30;
const AR_SYSTEM = `أنت خبير برمجي ومطوّر تجارب واقع معزز ثلاثية الأبعاد للمدارس في سلطنة عُمان، وخبير في المادة الدراسية نفسها.
مهمتك: تحويل طلب المعلم إلى مشهد ثلاثي الأبعاد كامل ودقيق وتفاعلي، يُبنى فيه كل شخصية وكل شيء مذكور في الطلب دون إهمال أي عنصر.

## المدخلات
المادة، الصف، عنوان الدرس، وملاحظات المعلم (قد تذكر شخصيات أو أشياء أو مواقف محددة).

## طريقة العمل (نفّذها بالترتيب)
1. التحليل: استخرج من الطلب قائمة كاملة بكل الشخصيات (أشخاص، حيوانات، كائنات) وكل الأشياء (أدوات، أجهزة، مبانٍ، نباتات، أعضاء، أماكن) والأحداث المطلوبة. إن لم يذكر المعلم شيئًا، فاختر ما يحتاجه الدرس فعلًا.
2. التخطيط: لكل عنصر حدّد شكله الحقيقي وأجزاءه وألوانه ونِسَب أبعاده وموقعه بالنسبة للعناصر الأخرى، ثم حدد الحركة التي تشرح الدرس.
3. البناء: ابنِ كل عنصر من عدة أشكال أساسية مجمّعة في Group، بنسب واقعية، لا من شكل واحد بسيط.
4. الحركة: حرّك العملية المشروحة (تدفق، دوران، نمو، مشي، تفاعل) باستخدام onUpdate.
5. الربط بالشرح: كل جزء يُذكر في الشرح يجب أن يحمل label() بالاسم العربي نفسه حرفيًا، وكل خطوة تنقل الكاميرا إليه وتُظهر ما تتحدث عنه.
6. التفاعل: لوحة تحكم (أزرار ومنزلقات) تغيّر النموذج تغييرًا مفيدًا تعليميًا، ومربع معلومات.
7. التقويم: 6–8 أسئلة اختيار من متعدد مع سبب الإجابة الصحيحة.
8. المراجعة الذاتية قبل الإخراج: تأكد أن كل عنصر في القائمة بُني، وأن المعلومات صحيحة، وأن الكود يعمل دون أخطاء.

## وصفات بناء العناصر
- الشخصية البشرية: جسم (Capsule) + رأس (Sphere) + ذراعان ورجلان بمفاصل (Group لكل مفصل لتحريكها) + ملابس مناسبة للبيئة العُمانية (دشداشة وكمّة للرجال، لباس محتشم للنساء، زي مدرسي للطلاب). الوجه مبسّط بلا تفاصيل واقعية.
- الحيوان: جسم وأطراف ورأس وذيل بنِسَبه الحقيقية (الجمل بسنامه، الصقر بجناحيه المفرودين…) مع حركة طبيعية.
- النبات: جذر وساق وأوراق وزهرة بأجزائها (سبلات، بتلات، أسدية، مدقة) عند الحاجة.
- الأجهزة والآلات: أجزاء منفصلة قابلة للتفكيك (explode) مع شرح وظيفة كل جزء.
- الأعضاء والكائنات الدقيقة: مقطع عرضي بشفافية لإظهار الداخل (القلب بحجراته الأربع وصماماته…).
- المباني والأماكن: نِسَب معمارية صحيحة. أي درس عن الكعبة أو المسجد الحرام أو الحج أو العمرة يستخدم buildHaram() إلزاميًا ولا يرسمها من جديد.
- الخرائط والتضاريس: إحداثيات تقريبية صحيحة مع تنبيه «تقريبية».
- الرياضيات: أشكال بقياسات دقيقة وأرقام تتحدث مع الحركة.

## قواعد الدقة (إلزامية)
- كل معلومة علمية أو رياضية أو جغرافية أو تاريخية أو شرعية يجب أن تكون صحيحة ومتوافقة مع المناهج العُمانية. لا تذكر رقمًا لست متأكدًا منه.
- لا تُصوَّر الأنبياء ولا الصحابة ولا الملائكة بأي شكل، ولا يُكتب نص قرآني داخل المشهد.
- الطقوس الدينية تُعرض بترتيبها وكيفيتها الصحيحة (مثل الطواف عكس عقارب الساعة والكعبة عن يسار الطائف).
- لغة عربية فصحى سهلة تناسب الصف (ولدروس الإنجليزية: كلمات إنجليزية مع معناها العربي).

## الأدوات المتاحة (مكتبة المنصة)
setHome, M, mesh, label, cylBetween, setCyl, clickable, onUpdate, tweenVal, camTo, canvasTex, buildHaram, sayNow, toast,
UI.reset, UI.sec, UI.slider, UI.buttons, UI.info, UI.steps, UI.quiz, THREE (r147), E.root.

## شروط الكود
- أخرج جسم الدالة فقط داخل كتلة \`\`\`js واحدة، وابدأ دائمًا بـ UI.reset(…).
- المشهد بعرض 8–10 وحدات تقريبًا وارتفاع حتى 6، والأرض عند y = 0.
- ممنوع: fetch، import، eval، الوصول إلى document/window، والحلقات اللانهائية. عدد الجسيمات أقل من 400.
- يجب أن يعمل دون أي خطأ في three.js r147.

## تفاصيل الأدوات (التواقيع الدقيقة)
- setHome([x,y,z],[tx,ty,tz]) موضع الكاميرا الابتدائي وهدفها.
- M(color, opts) -> MeshStandardMaterial (opts: transparent, opacity, metalness, roughness, emissive, side…).
- mesh(geometry, material, parent?) -> يضيف Mesh للمشهد أو لمجموعة THREE.Group (أنشئ المجموعات بـ new THREE.Group() وأضفها بـ E.root.add(group)).
- label(text, [x,y,z], {size:0.18-0.4, parent, color, bg:"none"}) -> نص عربي يواجه الكاميرا؛ sprite.userData.set(نص جديد) لتغييره.
- cylBetween(a, b, radius, material, parent) -> أسطوانة بين نقطتين (عظام، أسلاك، أوعية، أعمدة). setCyl(m, a, b) لتحريكها.
- clickable(object, fn) · onUpdate((dt, t)=>{…}) · tweenVal(from, to, seconds, fn, done) · camTo([x,y,z],[tx,ty,tz], seconds).
- canvasTex(w, h, (ctx, w, h)=>{…}) -> CanvasTexture لتفاصيل الأسطح (نقوش، خرائط، أرقام، لوحات).
- buildPerson({type:"man"|"woman"|"boy"|"girl"|"pilgrim", color, height:1.7, parent}) -> شخصية جاهزة بملابس عُمانية ومفاصل متحركة؛ تُرجع Group فيها userData.joints = {head, lArm, rArm, lLeg, rLeg} ودوال userData.walk(t) و userData.wave(t) و userData.point(dir). استخدمها لكل شخصية بشرية.
- buildHaram(group, {crowd:400, labels:true}) -> نموذج دقيق جاهز للكعبة والمطاف ومقام إبراهيم والحِجر والصفا والمروة (الوحدة = 10 م).
- sayNow(text, "ar-SA"|"en-US") نطق · toast(text) رسالة قصيرة.
- UI.reset(title, subtitle) أولًا دائمًا · UI.sec(title) قسم · UI.slider(sec, {label, min, max, step, value, unit, onInput}) · UI.buttons(sec, [{t:"نص", on:()=>{}}], {radio:true}) · UI.info() عنصر للمعلومات (.innerHTML).
- UI.steps([{t:"العنوان", d:"الشرح", run:()=>{…}}]) من 5 إلى 8 خطوات · UI.quiz([[السؤال, [الصحيحة, خطأ1, خطأ2, خطأ3], سبب الإجابة], …]) الخيار الأول هو الصحيح (يُخلط تلقائيًا).
- متاح أيضًا: lerp, clamp, ease, D2R, E (E.root, E.camera, E.scene).
أعد كتلة الكود فقط.`;
function extractText(out) {
  if (!out) return "";
  if (typeof out === "string") return out;
  if (typeof out.response === "string") return out.response;
  if (typeof out.output_text === "string") return out.output_text;
  if (out.choices && out.choices[0] && out.choices[0].message) return out.choices[0].message.content || "";
  if (Array.isArray(out.output)) return out.output.filter(o => o.type === "message").flatMap(o => (o.content || []).map(c => c.text || "")).join("");
  if (out.result) return extractText(out.result);
  return "";
}
async function callLLM(env, system, user, maxTokens) {
  if (env.ANTHROPIC_API_KEY) {
    const r = await fetch("https://api.anthropic.com/v1/messages", { method: "POST",
      headers: { "content-type": "application/json", "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: env.ANTHROPIC_MODEL || "claude-sonnet-5-5", max_tokens: maxTokens, system, messages: [{ role: "user", content: user }] }) });
    const d = await r.json().catch(() => ({}));
    if (r.ok) return { text: (d.content || []).map(c => c.text || "").join(""), engine: "claude" };
  }
  if (!env.AI) throw new Error("capability_disabled");
  try {
    const out = await env.AI.run("@cf/openai/gpt-oss-120b", { instructions: system, input: user, reasoning: { effort: "medium" }, max_output_tokens: maxTokens });
    const text = extractText(out); if (text.trim()) return { text, engine: "gpt-oss-120b" };
  } catch (e) {}
  const out = await env.AI.run(AI_MODEL, { messages: [{ role: "system", content: system }, { role: "user", content: user }], max_tokens: 6000, temperature: 0.3 });
  return { text: extractText(out), engine: "llama-3.3-70b" };
}
async function handleAR(db, env, request, user) {
  if (request.method === "GET") return json({ available: !!env.AI || !!env.ANTHROPIC_API_KEY, engine: env.ANTHROPIC_API_KEY ? "claude" : "gpt-oss-120b" });
  if (!user) return json({ error: "session_expired" }, 401);
  if (!(await bumpUsage(db, "ar:" + (user.teacherId || user.role), AR_PER_HOUR))) return json({ error: "rate_limited" }, 429);
  const b = await request.json().catch(() => ({}));
  const subject = clip(b.subject, 80), grade = clip(b.grade, 60), topic = clip(b.topic, 300), req = clip(b.request, 1500), code = clip(b.code, 60000), err = clip(b.error, 1500);
  let prompt;
  if (b.mode === "edit") prompt = `Lesson: ${topic} — ${subject} — ${grade}.\nCurrent scene code:\n\`\`\`js\n${code}\n\`\`\`\nThe teacher asks for this change (Arabic): «${req}».\nApply it carefully, keep everything else working and accurate, and return the FULL updated code.`;
  else if (b.mode === "fix") prompt = `Lesson: ${topic} — ${subject} — ${grade}.\nThis scene code failed with the error: ${err}\n\`\`\`js\n${code}\n\`\`\`\nFix the bug(s) and return the FULL corrected code. Keep the content and accuracy.`;
  else prompt = `Build a complete, accurate, interactive 3D/AR scene for this lesson.\nSubject: ${subject}\nGrade: ${grade}\nLesson: ${topic}\n${req ? "Teacher notes: " + req + "\n" : ""}Plan the model's real structure and proportions first (silently), then write the code.`;
  try {
    const { text, engine } = await callLLM(env, AR_SYSTEM, prompt, 14000);
    const m = String(text).match(/```(?:js|javascript)?\s*([\s\S]*?)```/i);
    const out = (m ? m[1] : String(text)).trim();
    if (!out || !/UI\.reset/.test(out)) return json({ error: "bad_output", engine }, 502);
    return json({ code: out, engine });
  } catch (e) {
    const msg = String(e && e.message || e);
    return json({ error: /limit|quota|429|neurons/i.test(msg) ? "rate_limited" : "upstream_error" }, 502);
  }
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
          case "/api/credentials": {
            const user = await currentUser(db, request);
            if (!user) return json({ error: "unauthorized" }, 401);
            if (user.role !== "admin") return json({ error: "forbidden" }, 403);
            const list = (await getDoc(db, "school/teachers"))?.list || [];
            const out = [];
            for (const t of list) out.push({ id: t.id, username: t.username || "", code: t.codeEnc ? await decryptCode(db, t.codeEnc) : "", hasCode: !!t.code });
            return json({ list: out });
          }
          case "/api/portfolio": return handlePortfolio(db, request, await currentUser(db, request), url);
          case "/api/image": return handleImage(db, env, request, await currentUser(db, request));
          case "/api/ar": return handleAR(db, env, request, request.method === "GET" ? null : await currentUser(db, request));
          case "/api/videos": return handleVideos(db, request, await currentUser(db, request), url);
          case "/api/ai": return handleAI(db, env, request, request.method === "GET" ? null : await currentUser(db, request));
          default:
            if (url.pathname === "/api/files" || url.pathname.startsWith("/api/files/")) return handleFiles(db, request, await currentUser(db, request), url);
            return json({ error: "not_found" }, 404);
        }
      } catch (err) {
        return json({ error: "server_error" }, 500);
      }
    }
    const asset = /^\/admin\/?$/i.test(url.pathname)
      ? await env.ASSETS.fetch(new Request(new URL("/", url), request))
      : await env.ASSETS.fetch(request);
    // Always revalidate the app page so every update shows up immediately (no stale copies).
    const res = new Response(asset.body, asset);
    if ((res.headers.get("content-type") || "").includes("text/html")) res.headers.set("cache-control", "no-cache, must-revalidate");
    return res;
  },
};
