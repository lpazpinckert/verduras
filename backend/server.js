const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const { DATABASE_URL, JWT_SECRET, FRONTEND_URL, ALLOW_REGISTER, INVITE_CODE } = process.env;
const TABLES = ["days", "orders", "pagos"];
const PORT = process.env.PORT || 3000;
if (!DATABASE_URL || !JWT_SECRET) {
  console.error("Faltan las variables DATABASE_URL y/o JWT_SECRET");
  process.exit(1);
}

const local = /localhost|127\.0\.0\.1/.test(DATABASE_URL);
const pool = new Pool({ connectionString: DATABASE_URL, ssl: local ? false : { rejectUnauthorized: false } });

const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: FRONTEND_URL ? FRONTEND_URL.split(",").map(s => s.trim()) : true }));
app.use(express.json({ limit: "1mb" }));

const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: "Error del servidor" }); });
const sign = u => jwt.sign({ uid: u.id }, JWT_SECRET, { expiresIn: "60d" });
const auth = (req, res, next) => {
  const t = (req.headers.authorization || "").replace("Bearer ", "");
  try { req.uid = jwt.verify(t, JWT_SECRET).uid; next(); }
  catch (e) { res.status(401).json({ error: "Sesión no válida" }); }
};
const FECHA = /^\d{4}-\d{2}-\d{2}$/;
const isObj = o => o && typeof o === "object" && !Array.isArray(o);

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())`);
  for (const t of TABLES)
    await pool.query(`CREATE TABLE IF NOT EXISTS ${t}(user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, fecha TEXT NOT NULL, items JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT now(), PRIMARY KEY(user_id, fecha))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS config(user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, cfg JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT now())`);
}

app.get("/api/health", (req, res) => res.json({ ok: true }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });

app.post("/api/auth/register", limiter, wrap(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const pw = String(req.body.password || "");
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Correo no válido" });
  if (pw.length < 6) return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });
  const n = (await pool.query("SELECT COUNT(*)::int AS n FROM users")).rows[0].n;
  const code = String(req.body.code || "").trim();
  if (n > 0 && ALLOW_REGISTER !== "true") return res.status(403).json({ error: "El registro está cerrado" });
  if (n > 0 && INVITE_CODE && code !== INVITE_CODE) return res.status(403).json({ error: "Código de invitación incorrecto" });
  if ((await pool.query("SELECT 1 FROM users WHERE email=$1", [email])).rowCount) return res.status(409).json({ error: "Ese correo ya existe" });
  const u = (await pool.query("INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id", [email, await bcrypt.hash(pw, 10)])).rows[0];
  res.json({ token: sign(u) });
}));

app.post("/api/auth/login", limiter, wrap(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const u = (await pool.query("SELECT id,password_hash FROM users WHERE email=$1", [email])).rows[0];
  if (!u || !(await bcrypt.compare(String(req.body.password || ""), u.password_hash)))
    return res.status(401).json({ error: "Correo o contraseña incorrectos" });
  res.json({ token: sign(u) });
}));

app.get("/api/data", auth, wrap(async (req, res) => {
  const out = { days: {}, orders: {}, pagos: {}, cfg: null };
  for (const t of TABLES)
    (await pool.query(`SELECT fecha, items FROM ${t} WHERE user_id=$1`, [req.uid])).rows.forEach(r => out[t][r.fecha] = r.items);
  const c = (await pool.query("SELECT cfg FROM config WHERE user_id=$1", [req.uid])).rows[0];
  if (c) out.cfg = c.cfg;
  res.json(out);
}));

for (const t of TABLES) {
  app.put(`/api/${t}/:fecha`, auth, wrap(async (req, res) => {
    if (!FECHA.test(req.params.fecha) || !isObj(req.body.items)) return res.status(400).json({ error: "Datos no válidos" });
    await pool.query(
      `INSERT INTO ${t}(user_id,fecha,items) VALUES($1,$2,$3) ON CONFLICT (user_id,fecha) DO UPDATE SET items=EXCLUDED.items, updated_at=now()`,
      [req.uid, req.params.fecha, JSON.stringify(req.body.items)]);
    res.json({ ok: true });
  }));
  app.delete(`/api/${t}/:fecha`, auth, wrap(async (req, res) => {
    if (!FECHA.test(req.params.fecha)) return res.status(400).json({ error: "Fecha no válida" });
    await pool.query(`DELETE FROM ${t} WHERE user_id=$1 AND fecha=$2`, [req.uid, req.params.fecha]);
    res.json({ ok: true });
  }));
}

app.put("/api/config", auth, wrap(async (req, res) => {
  if (!isObj(req.body.cfg)) return res.status(400).json({ error: "Datos no válidos" });
  await pool.query(
    `INSERT INTO config(user_id,cfg) VALUES($1,$2) ON CONFLICT (user_id) DO UPDATE SET cfg=EXCLUDED.cfg, updated_at=now()`,
    [req.uid, JSON.stringify(req.body.cfg)]);
  res.json({ ok: true });
}));

// Opcional: si la carpeta frontend está junto al backend, también se sirve desde aquí
const fe = path.join(__dirname, "..", "frontend");
if (fs.existsSync(fe)) app.use(express.static(fe));

init().then(() => app.listen(PORT, () => console.log("Servidor listo en puerto " + PORT)))
  .catch(e => { console.error("No se pudo iniciar la base de datos:", e.message); process.exit(1); });
