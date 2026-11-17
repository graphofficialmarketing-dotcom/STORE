// API สำหรับบอร์ดโปรโมชั่น
// GET  /api/data            -> อ่านข้อมูล (หน้าร้านใช้ ไม่ต้องใช้รหัสผ่าน)
// POST /api/data            -> ตรวจรหัสผ่าน / บันทึกข้อมูล (ต้องส่ง header x-admin-password)
//
// ใช้ฐานข้อมูล Upstash Redis จาก Vercel Marketplace ผ่าน REST API (ไม่ต้องติดตั้ง package เพิ่ม)
// ตัวแปรที่ต้องมีใน Vercel:
//   KV_REST_API_URL + KV_REST_API_TOKEN   (หรือ UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN)
//   ADMIN_PASSWORD                         รหัสผ่านของทีมการตลาด

const crypto = require("crypto");

const KEY = "promo_board:v1";
const MAX_BYTES = 900 * 1024;

function redisConfig() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  return url && token ? { url: url.replace(/\/+$/, ""), token } : null;
}

async function redis(cfg, command) {
  const r = await fetch(cfg.url, {
    method: "POST",
    headers: { Authorization: "Bearer " + cfg.token, "Content-Type": "application/json" },
    body: JSON.stringify(command),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) throw new Error(j.error || "redis http " + r.status);
  return j.result;
}

async function readDoc(cfg) {
  const raw = await redis(cfg, ["GET", KEY]);
  if (!raw) return { state: null, version: 0 };
  try {
    const doc = JSON.parse(raw);
    return { state: doc.state || null, version: Number(doc.version) || 0 };
  } catch (e) {
    return { state: null, version: 0 };
  }
}

function samePassword(given, expected) {
  const a = crypto.createHash("sha256").update(String(given || "")).digest();
  const b = crypto.createHash("sha256").update(String(expected || "")).digest();
  return crypto.timingSafeEqual(a, b);
}

function validState(s) {
  return (
    s && typeof s === "object" &&
    Array.isArray(s.branches) && Array.isArray(s.items) &&
    s.branches.every((b) => b && typeof b.id === "string" && typeof b.name === "string") &&
    s.items.every((p) => p && typeof p.id === "string" && typeof p.title === "string" &&
      /^\d{4}-\d{2}-\d{2}$/.test(p.start || "") && /^\d{4}-\d{2}-\d{2}$/.test(p.end || ""))
  );
}

function send(res, status, body) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.status(status).send(JSON.stringify(body));
}

module.exports = async function handler(req, res) {
  const cfg = redisConfig();
  try {
    if (req.method === "GET") {
      if (!cfg) return send(res, 200, { configured: false, state: null, version: 0 });
      const doc = await readDoc(cfg);
      return send(res, 200, { configured: true, state: doc.state, version: doc.version });
    }

    if (req.method !== "POST") return send(res, 405, { error: "method_not_allowed" });

    const expected = process.env.ADMIN_PASSWORD;
    if (!expected) return send(res, 500, { error: "no_password" });
    if (!samePassword(req.headers["x-admin-password"], expected)) return send(res, 401, { error: "wrong_password" });

    let body = req.body;
    if (typeof body === "string") { try { body = JSON.parse(body); } catch (e) { body = {}; } }
    body = body || {};

    if (body.action === "check") return send(res, 200, { ok: true });

    if (body.action === "save") {
      if (!cfg) return send(res, 503, { error: "no_database" });
      if (!validState(body.state)) return send(res, 400, { error: "invalid_state" });
      const current = await readDoc(cfg);
      if (Number(body.version) !== current.version) {
        return send(res, 409, { error: "conflict", state: current.state || body.state, version: current.version });
      }
      const doc = JSON.stringify({ version: current.version + 1, savedAt: new Date().toISOString(), state: body.state });
      if (Buffer.byteLength(doc) > MAX_BYTES) return send(res, 413, { error: "too_large" });
      await redis(cfg, ["SET", KEY, doc]);
      return send(res, 200, { ok: true, version: current.version + 1 });
    }

    return send(res, 400, { error: "unknown_action" });
  } catch (e) {
    console.error(e);
    return send(res, 500, { error: "server_error" });
  }
};
