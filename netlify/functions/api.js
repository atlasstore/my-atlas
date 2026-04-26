/**
 * ATLAS BACKEND — netlify/functions/api.js  v3
 * ════════════════════════════════════════════════════════════════
 * Audit fixes applied in this version:
 *   BUG-01  PayPal re-render handled client-side (total tracking)
 *   BUG-02  Newsletter /api/subscribe endpoint — saves to PostgreSQL
 *   BUG-03  _shippingFormData unified to window only (client fix)
 *   BUG-04  Cart escape reset (client fix)
 *   BUG-05  Rate limiter moved to PostgreSQL — survives cold starts
 *   BUG-06  CSRF tokens stored in PostgreSQL — survives cold starts
 *   BUG-08  parseInt quantity operator precedence fixed
 *   ISSUE-08 PUT /api/admin/products/:id endpoint added
 *   SEC-03  Phone validation added
 *   SEC-04  PAYPAL_ENV strict validation
 *   ISSUE-09 Orders endpoint supports ?status&country&from filtering
 *   ISSUE-11 revoked_tokens cleanup on startup
 * ════════════════════════════════════════════════════════════════
 */

"use strict";

require("dotenv").config();

const express      = require("express");
const path         = require("path");
const crypto       = require("crypto");
const jwt          = require("jsonwebtoken");
const { Pool }     = require("pg");
const bcrypt       = require("bcrypt");
const serverless   = require("serverless-http");

const app = express();

// ── Logger ────────────────────────────────────────────────────
function log(level, msg, detail) {
  const line = `[${new Date().toISOString()}] [${level}] ${msg}`;
  if (level === "ERROR") process.stderr.write(line + (detail ? `\n  >> ${detail}` : "") + "\n");
  else process.stdout.write(line + "\n");
}
function maskIp(ip) {
  if (!ip) return "0.0.0.0";
  const parts = ip.split(".");
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.x.x`;
  return ip.split(":").slice(0, 4).join(":") + "::";
}

// ── Environment validation ────────────────────────────────────
const JWT_SECRET           = process.env.JWT_SECRET;
const ADMIN_EMAIL          = process.env.ADMIN_EMAIL;
const ADMIN_PASS_HASH      = process.env.ADMIN_PASS_HASH;
const PAYPAL_CLIENT_ID     = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET || "";
// SEC-04: strict PAYPAL_ENV validation
const PAYPAL_ENV_RAW       = (process.env.PAYPAL_ENV || "sandbox").toLowerCase();
const CJ_API_KEY           = process.env.CJ_API_KEY   || "";
const CJ_EMAIL             = process.env.CJ_EMAIL     || "";
const DATABASE_URL         = process.env.DATABASE_URL;

function fatalEnvError(msg) {
  console.error(`\n\x1b[31m[FATAL] ${msg}\x1b[0m\n`);
  process.exit(1);
}

if (!JWT_SECRET || JWT_SECRET.length < 32 || JWT_SECRET.startsWith("REPLACE_"))
  fatalEnvError("JWT_SECRET is missing, too short, or a placeholder.");
if (!ADMIN_EMAIL || !ADMIN_PASS_HASH || ADMIN_PASS_HASH.startsWith("REPLACE_") || !ADMIN_PASS_HASH.startsWith("$2"))
  fatalEnvError("ADMIN_EMAIL or ADMIN_PASS_HASH is missing/invalid. Run: node generate-hash.js");
if (!PAYPAL_CLIENT_ID || PAYPAL_CLIENT_ID.startsWith("REPLACE_") || PAYPAL_CLIENT_ID.startsWith("YOUR_"))
  fatalEnvError("PAYPAL_CLIENT_ID is not configured.");
if (!["sandbox","production"].includes(PAYPAL_ENV_RAW))
  fatalEnvError("PAYPAL_ENV must be exactly 'sandbox' or 'production'.");
if (PAYPAL_ENV_RAW === "production" && (!PAYPAL_CLIENT_SECRET || PAYPAL_CLIENT_SECRET.startsWith("YOUR_")))
  fatalEnvError("PAYPAL_CLIENT_SECRET must be set when PAYPAL_ENV=production.");
if (!DATABASE_URL || DATABASE_URL.startsWith("YOUR_") || DATABASE_URL.startsWith("REPLACE_"))
  fatalEnvError("DATABASE_URL is not configured. Provide a PostgreSQL connection string.");

const PAYPAL_ENV = PAYPAL_ENV_RAW;

// ── PostgreSQL pool ───────────────────────────────────────────
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 5000,
});

async function query(sql, params = []) {
  const client = await pool.connect();
  try {
    const res = await client.query(sql, params);
    return res.rows;
  } finally {
    client.release();
  }
}
async function queryOne(sql, params = []) {
  const rows = await query(sql, params);
  return rows[0] || null;
}

// ── Schema bootstrap ──────────────────────────────────────────
async function initDb() {
  await query(`
    CREATE TABLE IF NOT EXISTS products (
      id           SERIAL PRIMARY KEY,
      name         TEXT    NOT NULL CHECK(length(name) > 0),
      price        NUMERIC(10,2) NOT NULL CHECK(price > 0),
      category     TEXT    NOT NULL DEFAULT 'General',
      description  TEXT    NOT NULL DEFAULT '',
      image1       TEXT    NOT NULL DEFAULT '',
      images       TEXT    NOT NULL DEFAULT '[]',
      supplier_sku TEXT    NOT NULL DEFAULT '',
      created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS orders (
      id              TEXT PRIMARY KEY,
      paypal_order_id TEXT    NOT NULL DEFAULT '' UNIQUE,
      items           TEXT    NOT NULL DEFAULT '[]',
      shipping        TEXT    NOT NULL DEFAULT '{}',
      customer_email  TEXT    NOT NULL DEFAULT '',
      full_name       TEXT    NOT NULL DEFAULT '',
      phone           TEXT    NOT NULL DEFAULT '',
      country         TEXT    NOT NULL DEFAULT '',
      city            TEXT    NOT NULL DEFAULT '',
      address         TEXT    NOT NULL DEFAULT '',
      zip_code        TEXT    NOT NULL DEFAULT '',
      total           NUMERIC(10,2) NOT NULL DEFAULT 0 CHECK(total >= 0),
      status          TEXT    NOT NULL DEFAULT 'paid',
      cj_order_id     TEXT    NOT NULL DEFAULT '',
      created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS login_attempts (
      ip            TEXT PRIMARY KEY,
      count         INTEGER NOT NULL DEFAULT 0,
      blocked_until TIMESTAMPTZ DEFAULT NULL,
      updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS revoked_tokens (
      jti        TEXT PRIMARY KEY,
      expires_at TIMESTAMPTZ NOT NULL
    );

    -- BUG-06: CSRF tokens in PostgreSQL (survives cold starts)
    CREATE TABLE IF NOT EXISTS csrf_tokens (
      token      TEXT PRIMARY KEY,
      expires_at TIMESTAMPTZ NOT NULL
    );

    -- BUG-05: API rate limiting in PostgreSQL
    CREATE TABLE IF NOT EXISTS rate_limits (
      ip         TEXT PRIMARY KEY,
      count      INTEGER NOT NULL DEFAULT 0,
      window_end TIMESTAMPTZ NOT NULL
    );

    -- BUG-02: Newsletter subscribers
    CREATE TABLE IF NOT EXISTS newsletters (
      email      TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // ISSUE-11: clean up expired tokens on startup
  await query("DELETE FROM revoked_tokens WHERE expires_at < NOW()");
  await query("DELETE FROM csrf_tokens WHERE expires_at < NOW()");
  await query("DELETE FROM rate_limits WHERE window_end < NOW()");

  log("INFO", "Database schema verified / initialised");
}

let _dbReady = false;
async function ensureDb() {
  if (_dbReady) return;
  await initDb();
  _dbReady = true;
}

// ── Input helpers ─────────────────────────────────────────────
function str(v, max = 1000) {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return "";
  return String(v).trim().slice(0, max);
}
function sanitize(v, max = 1000) {
  return str(v, max)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;")
    .replace(/javascript\s*:/gi, "").replace(/data\s*:/gi, "");
}
function isEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e || "")); }
// SEC-03: phone validation
function isValidPhone(p) { return /^[+\d\s\-().]{7,20}$/.test(String(p || "")); }
function posFloat(v, maxV = 999999) {
  const n = parseFloat(v);
  return (!isNaN(n) && n > 0 && n <= maxV) ? Math.round(n * 100) / 100 : null;
}

// ════════════════════════════════════════════════════════════
// Express Middleware
// ════════════════════════════════════════════════════════════
app.set("trust proxy", 1);
app.use(express.json({ limit: "512kb" }));
app.use(express.urlencoded({ extended: false, limit: "512kb" }));

// Lazy DB init
app.use(async (_req, _res, next) => {
  try { await ensureDb(); next(); }
  catch (e) { log("ERROR", "DB init failed", e.message); next(e); }
});

// Security headers
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options",  "nosniff");
  res.setHeader("X-Frame-Options",         "DENY");
  res.setHeader("X-XSS-Protection",        "1; mode=block");
  res.setHeader("Referrer-Policy",         "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy",      "camera=(), microphone=(), geolocation=()");
  res.setHeader("Content-Security-Policy",
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://www.paypal.com https://www.paypalobjects.com https://cdn.jsdelivr.net https://fonts.googleapis.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data: https:; " +
    "connect-src 'self' https://www.paypal.com https://api.sandbox.paypal.com https://api-m.paypal.com https://api-m.sandbox.paypal.com; " +
    "frame-src https://www.paypal.com https://www.sandbox.paypal.com;"
  );
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  next();
});

// CORS
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || null;
app.use((req, res, next) => {
  const reqOrigin = req.headers.origin || "";
  if (ALLOWED_ORIGIN && reqOrigin === ALLOWED_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// Block sensitive file extensions
app.use((req, res, next) => {
  const p = req.path.toLowerCase();
  if (p.endsWith(".db") || p.endsWith(".log") || p.endsWith(".env"))
    return res.status(404).end();
  next();
});

// BUG-05: API rate limiter — PostgreSQL backed, survives cold starts
app.use("/api", async (req, res, next) => {
  const ip = req.ip || "0.0.0.0";
  try {
    const now = new Date();
    const windowEnd = new Date(now.getTime() + 60000); // 1-min window
    // Upsert: if window expired, reset; otherwise increment
    await query(`
      INSERT INTO rate_limits (ip, count, window_end) VALUES ($1, 1, $2)
      ON CONFLICT(ip) DO UPDATE SET
        count = CASE WHEN rate_limits.window_end < NOW() THEN 1
                     ELSE rate_limits.count + 1 END,
        window_end = CASE WHEN rate_limits.window_end < NOW() THEN $2
                          ELSE rate_limits.window_end END
    `, [ip, windowEnd.toISOString()]);
    const row = await queryOne("SELECT count FROM rate_limits WHERE ip=$1", [ip]);
    if (row && row.count > 200) return res.status(429).json({ error: "Too many requests." });
  } catch (_) { /* non-fatal — allow through if rate limit table fails */ }
  next();
});

app.use((req, _res, next) => { log("INFO", `${req.method} ${req.path}`); next(); });

// ── JWT ───────────────────────────────────────────────────────
function auth(req, res, next) {
  const hdr = req.headers["authorization"] || "";
  const tok = hdr.startsWith("Bearer ") ? hdr.slice(7) : "";
  if (!tok) return res.status(401).json({ success: false, message: "Authentication required." });
  try {
    const payload = jwt.verify(tok, JWT_SECRET, { algorithms: ["HS256"] });
    queryOne("SELECT 1 FROM revoked_tokens WHERE jti=$1", [payload.jti]).then(row => {
      if (row) return res.status(403).json({ success: false, message: "Session revoked. Please log in again." });
      req.user = payload;
      next();
    }).catch(() => res.status(500).json({ success: false, message: "Auth error." }));
  } catch (e) {
    res.status(403).json({ success: false, message: "Invalid or expired session. Please log in again." });
  }
}

function makeToken(email) {
  return jwt.sign(
    { sub: email, role: "admin", jti: crypto.randomBytes(16).toString("hex") },
    JWT_SECRET,
    { algorithm: "HS256", expiresIn: "8h" }
  );
}

// ── CSRF — BUG-06: PostgreSQL backed ─────────────────────────
async function newCsrf() {
  const t = crypto.randomBytes(32).toString("hex");
  const exp = new Date(Date.now() + 3600000).toISOString();
  await query(
    "INSERT INTO csrf_tokens (token, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    [t, exp]
  );
  return t;
}

async function checkCsrfMiddleware(req, res, next) {
  const t = req.headers["x-csrf-token"] || "";
  if (!t) return res.status(403).json({ success: false, message: "CSRF validation failed." });
  const row = await queryOne(
    "DELETE FROM csrf_tokens WHERE token=$1 AND expires_at > NOW() RETURNING token",
    [t]
  );
  if (!row) return res.status(403).json({ success: false, message: "CSRF token invalid or expired." });
  next();
}

// ── Brute-force ───────────────────────────────────────────────
async function loginGuard(ip) {
  const now = new Date().toISOString();
  await query(`
    INSERT INTO login_attempts (ip, count, blocked_until, updated_at) VALUES ($1, 1, NULL, $2)
    ON CONFLICT(ip) DO UPDATE SET
      count = CASE WHEN login_attempts.blocked_until IS NULL OR NOW() > login_attempts.blocked_until
                   THEN login_attempts.count + 1 ELSE login_attempts.count END,
      updated_at = EXCLUDED.updated_at
  `, [ip, now]);
  const row = await queryOne("SELECT * FROM login_attempts WHERE ip=$1", [ip]);
  if (row?.blocked_until && new Date() < new Date(row.blocked_until)) {
    const mins = Math.ceil((new Date(row.blocked_until) - Date.now()) / 60000);
    return { blocked: true, mins };
  }
  if (row?.count >= 5) {
    const until = new Date(Date.now() + 15 * 60000).toISOString();
    await query("UPDATE login_attempts SET blocked_until=$1, updated_at=$2 WHERE ip=$3", [until, now, ip]);
    return { blocked: true, mins: 15 };
  }
  return { blocked: false };
}
async function clearGuard(ip) {
  await query("UPDATE login_attempts SET count=0, blocked_until=NULL, updated_at=$1 WHERE ip=$2",
    [new Date().toISOString(), ip]);
}

// ── PayPal ────────────────────────────────────────────────────
const PP_BASE = PAYPAL_ENV === "production"
  ? "https://api-m.paypal.com"
  : "https://api-m.sandbox.paypal.com";

let _ppToken = null, _ppTokenExp = 0;

async function ppAccessToken() {
  if (!PAYPAL_CLIENT_SECRET) return null;
  if (_ppToken && Date.now() < _ppTokenExp) return _ppToken;
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), 10000);
  try {
    const res = await fetch(`${PP_BASE}/v1/oauth2/token`, {
      method: "POST",
      headers: {
        "Authorization": "Basic " + Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString("base64"),
        "Content-Type":  "application/x-www-form-urlencoded"
      },
      body: "grant_type=client_credentials",
      signal: ctrl.signal
    });
    if (!res.ok) {
      log("ERROR", `PayPal token request failed: ${res.status}`);
      return null;
    }
    const d = await res.json();
    if (d.access_token) {
      _ppToken    = d.access_token;
      _ppTokenExp = Date.now() + (d.expires_in - 60) * 1000;
    }
    return _ppToken || null;
  } catch (e) {
    log("ERROR", "PayPal token fetch failed", e.message);
    return null;
  } finally { clearTimeout(tid); }
}

async function verifyPayPal(orderId, expectedAmount) {
  if (!PAYPAL_CLIENT_SECRET) {
    log("WARN", "PayPal secret not set — skipping server-side verification (sandbox dev mode)");
    return { ok: true, skipped: true };
  }
  try {
    const tok = await ppAccessToken();
    if (!tok) return { ok: false, reason: "Could not obtain PayPal token" };
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), 10000);
    let r, o;
    try {
      r = await fetch(`${PP_BASE}/v2/checkout/orders/${orderId}`, {
        headers: { "Authorization": `Bearer ${tok}` },
        signal: ctrl.signal
      });
      o = await r.json();
    } finally { clearTimeout(tid); }
    if (o.status !== "COMPLETED") return { ok: false, reason: `Order status: ${o.status}` };
    const unit     = o.purchase_units?.[0];
    const currency = (unit?.amount?.currency_code || "").toUpperCase();
    const paid     = parseFloat(unit?.amount?.value || 0);
    if (currency !== "USD") return { ok: false, reason: `Currency ${currency} not accepted` };
    if (Math.abs(paid - expectedAmount) > 0.01) return { ok: false, reason: `Amount mismatch: paid ${paid}, expected ${expectedAmount}` };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: e.name === "AbortError" ? "PayPal API timeout" : "Verification error" };
  }
}

// ── CJ Dropshipping ───────────────────────────────────────────
const CJ_BASE = "https://developers.cjdropshipping.com/api2.0";
let _cjToken = null, _cjTokenExp = 0;

async function cjAccessToken() {
  if (!CJ_API_KEY || !CJ_EMAIL) return null;
  if (_cjToken && Date.now() < _cjTokenExp) return _cjToken;
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), 10000);
  try {
    const r = await fetch(`${CJ_BASE}/v1/authentication/getAccessToken`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: CJ_EMAIL, password: CJ_API_KEY }),
      signal: ctrl.signal
    });
    const d = await r.json();
    if (d?.data?.accessToken) {
      _cjToken    = d.data.accessToken;
      _cjTokenExp = Date.now() + 23 * 60 * 60 * 1000;
    }
    return _cjToken || null;
  } finally { clearTimeout(tid); }
}

async function submitToCJ({ orderId, items, shipping }) {
  if (!CJ_API_KEY || !CJ_EMAIL) { log("WARN", "CJ not configured — skipping"); return null; }
  const token = await cjAccessToken();
  if (!token) throw new Error("Could not obtain CJ access token");
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), 15000);
  try {
    const body = {
      orderNumber: orderId, shippingZip: shipping.zipCode,
      shippingCountry: shipping.country, shippingProvince: "",
      shippingCity: shipping.city, shippingAddress: shipping.address,
      shippingPhone: shipping.phone, shippingCustomerName: shipping.fullName,
      shippingName: "CJPacket Ordinary", remark: `ATLAS ${orderId}`,
      products: items.map(i => ({ vid: i.supplier_sku, quantity: i.quantity }))
    };
    const r = await fetch(`${CJ_BASE}/v1/shopping/order/createOrder`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "CJ-Access-Token": token },
      body: JSON.stringify(body),
      signal: ctrl.signal
    });
    const d = await r.json();
    if (!d?.data?.orderId) throw new Error(`CJ API error: ${JSON.stringify(d)}`);
    return String(d.data.orderId);
  } finally { clearTimeout(tid); }
}

function submitToCJAsync(orderId, items, shipping) {
  setImmediate(async () => {
    try {
      const row = await queryOne("SELECT cj_order_id FROM orders WHERE id=$1", [orderId]);
      if (row?.cj_order_id) return;
      const cjId = await submitToCJ({ orderId, items, shipping });
      if (cjId) {
        await query("UPDATE orders SET cj_order_id=$1 WHERE id=$2", [cjId, orderId]);
        log("INFO", `CJ order ${cjId} linked to ATLAS ${orderId}`);
      }
    } catch (e) { log("ERROR", `CJ submission failed for ${orderId}`, e.message); }
  });
}

// ════════════════════════════════════════════════════════════
// Routes
// ════════════════════════════════════════════════════════════

app.get("/api/config/paypal", (_req, res) =>
  res.json({ clientId: PAYPAL_CLIENT_ID || null })
);

app.get("/api/csrf-token", auth, async (_req, res) => {
  try {
    const t = await newCsrf();
    res.json({ token: t });
  } catch (e) { res.status(500).json({ success: false, message: "CSRF error." }); }
});

app.get("/api/status", async (_req, res) => {
  try {
    const p = await queryOne("SELECT COUNT(*) AS c FROM products");
    const o = await queryOne("SELECT COUNT(*) AS c FROM orders");
    res.json({ success: true, products: parseInt(p?.c||0), orders: parseInt(o?.c||0), time: new Date().toISOString() });
  } catch (e) { res.status(500).json({ success: false }); }
});

// ── Auth ──────────────────────────────────────────────────────
app.post("/api/admin/login", async (req, res) => {
  const ip = req.ip || "0.0.0.0";
  try {
    const existing = await queryOne("SELECT * FROM login_attempts WHERE ip=$1", [ip]);
    if (existing?.blocked_until && new Date() < new Date(existing.blocked_until)) {
      const mins = Math.ceil((new Date(existing.blocked_until) - Date.now()) / 60000);
      return res.status(429).json({ success: false, message: `Too many failed attempts. Try again in ${mins} minute(s).` });
    }
    const email = str(req.body?.email, 200).toLowerCase();
    const pass  = str(req.body?.password, 200);
    if (!email || !pass) return res.status(400).json({ success: false, message: "Email and password are required." });

    const emailOk = crypto.timingSafeEqual(
      Buffer.from(email.padEnd(200)),
      Buffer.from(ADMIN_EMAIL.toLowerCase().padEnd(200))
    );
    if (!emailOk) {
      await loginGuard(ip);
      return res.status(401).json({ success: false, message: "Invalid credentials." });
    }
    const match = await bcrypt.compare(pass, ADMIN_PASS_HASH);
    if (!match) {
      const guard = await loginGuard(ip);
      if (guard.blocked)
        return res.status(429).json({ success: false, message: `Account locked for ${guard.mins} minute(s).` });
      return res.status(401).json({ success: false, message: "Invalid credentials." });
    }
    await clearGuard(ip);
    const token = makeToken(ADMIN_EMAIL);
    log("INFO", `Admin login from ${maskIp(ip)}`);
    res.json({ success: true, token });
  } catch (e) {
    log("ERROR", "Login handler", e.message);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

app.get("/api/admin/verify", auth, (req, res) => {
  const token = makeToken(req.user.sub);
  res.json({ success: true, token });
});

app.post("/api/admin/logout", auth, async (req, res) => {
  try {
    await query(
      "INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      [req.user.jti, new Date(req.user.exp * 1000).toISOString()]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: "Logout error." }); }
});

// ── Newsletter — BUG-02: saves to DB ─────────────────────────
app.post("/api/subscribe", async (req, res) => {
  try {
    const email = str(req.body?.email, 200).toLowerCase();
    if (!isEmail(email)) return res.status(400).json({ success: false, message: "Invalid email address." });
    try {
      await query("INSERT INTO newsletters (email) VALUES ($1)", [email]);
      log("INFO", `Newsletter subscribe: ${email.split("@")[0]}@***`);
      res.json({ success: true, message: "Subscribed successfully!" });
    } catch (e) {
      if (e.code === "23505") return res.status(409).json({ success: false, message: "Already subscribed." });
      throw e;
    }
  } catch (e) {
    log("ERROR", "Subscribe", e.message);
    res.status(500).json({ success: false, message: "Subscription error." });
  }
});

// ── Stats ─────────────────────────────────────────────────────
app.get("/api/admin/stats", auth, async (req, res) => {
  try {
    const days  = Math.min(365, Math.max(1, parseInt(req.query.days) || 7));
    const since = new Date(Date.now() - days * 86400000).toISOString();
    const rows  = await query("SELECT total, items, created_at FROM orders WHERE created_at >= $1", [since]);
    const totalRevenue = rows.reduce((s, r) => s + parseFloat(r.total || 0), 0);
    const totalOrders  = rows.length;
    const avgOrder     = totalOrders ? totalRevenue / totalOrders : 0;
    const totalSold    = rows.reduce((s, r) => {
      let items = []; try { items = JSON.parse(r.items || "[]"); } catch (_) {}
      return s + items.reduce((ps, i) => ps + (i.quantity || 1), 0);
    }, 0);
    const dailySales = {};
    for (let i = 6; i >= 0; i--) {
      const d = new Date(); d.setDate(d.getDate() - i);
      dailySales[d.toISOString().split("T")[0]] = 0;
    }
    rows.forEach(r => {
      const k = new Date(r.created_at).toISOString().split("T")[0];
      if (dailySales[k] !== undefined) dailySales[k] += parseFloat(r.total || 0);
    });
    const pSales = {}, catSales = {};
    rows.forEach(r => {
      let items = []; try { items = JSON.parse(r.items || "[]"); } catch (_) {}
      items.forEach(i => {
        pSales[i.name] = (pSales[i.name] || 0) + (i.quantity || 1);
        const c = i.category || "General";
        catSales[c] = (catSales[c] || 0) + (i.price || 0) * (i.quantity || 1);
      });
    });
    const topProducts = Object.entries(pSales)
      .sort(([, a], [, b]) => b - a).slice(0, 5).map(([name, count]) => ({ name, count }));

    // Newsletter count
    const nlRow = await queryOne("SELECT COUNT(*) AS c FROM newsletters");
    const subscriberCount = parseInt(nlRow?.c || 0);

    res.json({
      success: true,
      totalRevenue: Math.round(totalRevenue * 100) / 100,
      totalOrders, avgOrder: Math.round(avgOrder * 100) / 100,
      totalSold, dailySales, topProducts, catSales, subscriberCount
    });
  } catch (e) { res.status(500).json({ success: false, message: "Error loading stats." }); }
});

// ── Products ──────────────────────────────────────────────────
app.get("/api/products", async (_req, res) => {
  try {
    const rows = await query("SELECT id,name,price,category,description,image1,images,created_at FROM products ORDER BY id DESC");
    res.json({ success: true, products: rows.map(r => ({ ...r, images: JSON.parse(r.images || "[]") })) });
  } catch (e) { res.status(500).json({ success: false, message: "Error loading products." }); }
});

app.get("/api/admin/products", auth, async (_req, res) => {
  try {
    const rows = await query("SELECT * FROM products ORDER BY id DESC");
    res.json({ success: true, products: rows.map(r => ({ ...r, images: JSON.parse(r.images || "[]") })) });
  } catch (e) { res.status(500).json({ success: false, message: "Error." }); }
});

// POST — add product
app.post("/api/admin/products", auth, checkCsrfMiddleware, async (req, res) => {
  try {
    const name        = sanitize(str(req.body.name,            200));
    const price       = posFloat(req.body.price, 999999);
    const category    = sanitize(str(req.body.category    || "General", 100));
    const description = sanitize(str(req.body.description || "",        2000));
    const supplierSku = sanitize(str(req.body.supplier_sku || "",       200));
    const image1      = sanitize(str(req.body.image1      || "",        500));
    const imagesRaw   = req.body.images;
    let imagesArr = [];
    if (Array.isArray(imagesRaw)) imagesArr = imagesRaw.map(u => sanitize(str(u, 500)));
    else if (typeof imagesRaw === "string") {
      try { imagesArr = JSON.parse(imagesRaw).map(u => sanitize(str(u, 500))); } catch (_) {}
    }
    if (!name)  return res.status(400).json({ success: false, message: "Product name is required." });
    if (!price) return res.status(400).json({ success: false, message: "A valid positive price is required." });
    const rows = await query(
      "INSERT INTO products (name,price,category,description,image1,images,supplier_sku) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *",
      [name, price, category, description, image1 || (imagesArr[0] || ""), JSON.stringify(imagesArr), supplierSku]
    );
    const product = rows[0];
    log("INFO", `Product added: id=${product.id}`);
    res.json({ success: true, product: { ...product, images: JSON.parse(product.images) } });
  } catch (e) { res.status(500).json({ success: false, message: "Error adding product." }); }
});

// ISSUE-08: PUT — edit existing product
app.put("/api/admin/products/:id", auth, checkCsrfMiddleware, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id) || id < 1) return res.status(400).json({ success: false, message: "Invalid product ID." });

    const existing = await queryOne("SELECT * FROM products WHERE id=$1", [id]);
    if (!existing) return res.status(404).json({ success: false, message: "Product not found." });

    const name        = sanitize(str(req.body.name        ?? existing.name,         200));
    const price       = posFloat(req.body.price ?? existing.price, 999999) || posFloat(existing.price, 999999);
    const category    = sanitize(str(req.body.category    ?? existing.category,     100));
    const description = sanitize(str(req.body.description ?? existing.description,  2000));
    const supplierSku = sanitize(str(req.body.supplier_sku ?? existing.supplier_sku,200));
    const image1      = sanitize(str(req.body.image1      ?? existing.image1,       500));
    const imagesRaw   = req.body.images;
    let imagesArr;
    if (Array.isArray(imagesRaw)) imagesArr = imagesRaw.map(u => sanitize(str(u, 500)));
    else if (typeof imagesRaw === "string") {
      try { imagesArr = JSON.parse(imagesRaw).map(u => sanitize(str(u, 500))); } catch (_) { imagesArr = JSON.parse(existing.images || "[]"); }
    } else {
      imagesArr = JSON.parse(existing.images || "[]");
    }
    if (!name)  return res.status(400).json({ success: false, message: "Product name is required." });
    if (!price) return res.status(400).json({ success: false, message: "A valid positive price is required." });

    const rows = await query(
      "UPDATE products SET name=$1,price=$2,category=$3,description=$4,image1=$5,images=$6,supplier_sku=$7 WHERE id=$8 RETURNING *",
      [name, price, category, description, image1, JSON.stringify(imagesArr), supplierSku, id]
    );
    const product = rows[0];
    log("INFO", `Product updated: id=${id}`);
    res.json({ success: true, product: { ...product, images: JSON.parse(product.images) } });
  } catch (e) { res.status(500).json({ success: false, message: "Error updating product." }); }
});

app.delete("/api/admin/products/:id", auth, checkCsrfMiddleware, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id) || id < 1) return res.status(400).json({ success: false, message: "Invalid product ID." });
    await query("DELETE FROM products WHERE id=$1", [id]);
    log("INFO", `Product deleted: id=${id}`);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, message: "Error deleting product." }); }
});

// ── Orders ────────────────────────────────────────────────────
app.post("/api/create-order", async (req, res) => {
  try {
    const paypalOrderId = str(req.body?.paypalOrderId, 200);
    const items         = req.body?.items;
    const shippingRaw   = req.body?.shippingAddress || {};

    if (!paypalOrderId || paypalOrderId.length < 4)
      return res.status(400).json({ success: false, message: "Invalid PayPal order ID." });
    if (!Array.isArray(items) || items.length === 0)
      return res.status(400).json({ success: false, message: "Cart is empty." });

    const fullName = str(shippingRaw.full_name || shippingRaw.name          || "", 200);
    const phone    = str(shippingRaw.phone                                    || "",  20);
    const country  = str(shippingRaw.country                                  || "", 100);
    const city     = str(shippingRaw.city                                     || "", 100);
    const address  = str(shippingRaw.address || shippingRaw.address_line_1   || "", 500);
    const zipCode  = str(shippingRaw.zip_code || shippingRaw.postal_code     || "",  20);
    const email    = str(shippingRaw.email                                    || "", 200);

    if (!fullName) return res.status(400).json({ success: false, message: "Full name is required." });
    // SEC-03: phone validation
    if (!phone || !isValidPhone(phone)) return res.status(400).json({ success: false, message: "A valid phone number is required (7–20 digits)." });
    if (!country) return res.status(400).json({ success: false, message: "Country is required." });
    if (!city)    return res.status(400).json({ success: false, message: "City is required." });
    if (!address) return res.status(400).json({ success: false, message: "Address is required." });
    if (!zipCode) return res.status(400).json({ success: false, message: "Zip / postal code is required." });

    // Server-side price calculation
    let serverTotal = 0;
    const verified  = [];
    for (const item of items) {
      const pid = parseInt(item.id, 10);
      const dbP = await queryOne("SELECT * FROM products WHERE id=$1", [pid]);
      if (!dbP) return res.status(400).json({ success: false, message: `Product ${pid} not found.` });
      // BUG-08: fixed operator precedence
      const qty = Math.min(99, Math.max(1, (parseInt(item.quantity, 10) || 1)));
      serverTotal += Math.round(parseFloat(dbP.price) * qty * 100) / 100;
      verified.push({ id: dbP.id, name: dbP.name, price: parseFloat(dbP.price), category: dbP.category, quantity: qty, supplier_sku: dbP.supplier_sku || "" });
    }
    serverTotal = Math.round(serverTotal * 100) / 100;

    const ppResult = await verifyPayPal(paypalOrderId, serverTotal);
    if (!ppResult.ok && !ppResult.skipped)
      return res.status(402).json({ success: false, message: `Payment verification failed: ${ppResult.reason}` });

    const customerEmail = isEmail(email) ? sanitize(email) : "";
    const orderId = `ORD-${Date.now()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;

    const client = await pool.connect();
    let txResult = { duplicate: false };
    try {
      await client.query("BEGIN");
      const dup = await client.query("SELECT id FROM orders WHERE paypal_order_id=$1 FOR UPDATE", [paypalOrderId]);
      if (dup.rows.length > 0) {
        txResult = { duplicate: true };
      } else {
        await client.query(
          `INSERT INTO orders (id,paypal_order_id,items,shipping,customer_email,full_name,phone,country,city,address,zip_code,total,status,cj_order_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          [
            orderId, paypalOrderId,
            JSON.stringify(verified), JSON.stringify(shippingRaw),
            customerEmail, sanitize(fullName), sanitize(phone),
            sanitize(country), sanitize(city), sanitize(address), sanitize(zipCode),
            serverTotal, "paid", ""
          ]
        );
      }
      await client.query("COMMIT");
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally { client.release(); }

    if (txResult.duplicate)
      return res.status(409).json({ success: false, message: "Order already processed." });

    log("INFO", `New order: ${orderId} total=${serverTotal}`);
    submitToCJAsync(orderId, verified, {
      fullName: sanitize(fullName), phone: sanitize(phone),
      country: sanitize(country), city: sanitize(city),
      address: sanitize(address), zipCode: sanitize(zipCode), email: customerEmail
    });

    res.json({ success: true, orderId, total: serverTotal });
  } catch (e) {
    log("ERROR", "Create order", e.message);
    res.status(500).json({ success: false, message: "Error creating order." });
  }
});

// ISSUE-09: Orders with filtering
app.get("/api/admin/orders", auth, async (req, res) => {
  try {
    const page    = Math.max(1, parseInt(req.query.page,  10) || 1);
    const limit   = Math.min(100, parseInt(req.query.limit, 10) || 20);
    const status  = str(req.query.status,  20) || null;
    const country = str(req.query.country, 10) || null;
    const from    = str(req.query.from,    30) || null;

    let where = [];
    let params = [];
    let idx = 1;
    if (status)  { where.push(`status=$${idx++}`);  params.push(status); }
    if (country) { where.push(`country=$${idx++}`); params.push(country); }
    if (from)    { where.push(`created_at>=$${idx++}`); params.push(from); }

    const whereClause = where.length ? "WHERE " + where.join(" AND ") : "";
    const countRow = await queryOne(`SELECT COUNT(*) AS c FROM orders ${whereClause}`, params);
    const total    = parseInt(countRow?.c || 0, 10);
    const rows     = await query(
      `SELECT * FROM orders ${whereClause} ORDER BY created_at DESC LIMIT $${idx++} OFFSET $${idx}`,
      [...params, limit, (page - 1) * limit]
    );
    res.json({
      success: true,
      orders: rows.map(r => {
        let parsedItems = []; try { parsedItems = JSON.parse(r.items || "[]"); } catch (_) {}
        let parsedShipping = {}; try { parsedShipping = JSON.parse(r.shipping || "{}"); } catch (_) {}
        return {
          id: r.id, paypalOrderId: r.paypal_order_id,
          items: parsedItems, shipping: parsedShipping,
          customerEmail: r.customer_email, fullName: r.full_name,
          phone: r.phone, country: r.country, city: r.city,
          address: r.address, zipCode: r.zip_code,
          total: parseFloat(r.total), status: r.status,
          cjOrderId: r.cj_order_id || "", date: r.created_at
        };
      }),
      total, page, pages: Math.ceil(total / limit)
    });
  } catch (e) { res.status(500).json({ success: false, message: "Error loading orders." }); }
});

// ── Subscribers admin list ─────────────────────────────────────
app.get("/api/admin/subscribers", auth, async (req, res) => {
  try {
    const rows = await query("SELECT email, created_at FROM newsletters ORDER BY created_at DESC");
    res.json({ success: true, subscribers: rows, total: rows.length });
  } catch (e) { res.status(500).json({ success: false, message: "Error." }); }
});

// ── CJ Webhook for shipping status updates ────────────────────
// ISSUE-10: endpoint to receive CJ shipment updates
app.post("/api/webhooks/cj", async (req, res) => {
  try {
    const { orderNumber, logisticsStatus, trackNo } = req.body || {};
    if (!orderNumber) return res.status(400).json({ success: false });
    const statusMap = { "SHIPPED": "shipped", "DELIVERED": "delivered", "PROCESSING": "processing" };
    const newStatus = statusMap[logisticsStatus] || null;
    if (newStatus) {
      await query("UPDATE orders SET status=$1 WHERE id=$2", [newStatus, str(orderNumber, 100)]);
      log("INFO", `CJ webhook: order ${orderNumber} → ${newStatus} (track: ${trackNo || "n/a"})`);
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false }); }
});

// 404 for unknown /api/*
app.use("/api", (_req, res) => res.status(404).json({ error: "Not found" }));

// Global error handler
app.use((err, _req, res, _next) => {
  log("ERROR", "Unhandled", err.message);
  res.status(500).json({ error: "Internal server error" });
});

process.on("uncaughtException",  e => log("ERROR", "Uncaught", e.message));
process.on("unhandledRejection", e => log("ERROR", "UnhandledRejection", String(e)));

const handler = serverless(app);
module.exports = { handler };
