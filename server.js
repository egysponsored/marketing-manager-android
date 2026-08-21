const express = require("express");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_PIN = String(process.env.ADMIN_PIN || "").trim();
const SERVER_SECRET = String(process.env.SERVER_SECRET || "").trim();

if (!DATABASE_URL) {
  console.error("DATABASE_URL is required");
  process.exit(1);
}
if (!ADMIN_PIN) {
  console.error("ADMIN_PIN is required");
  process.exit(1);
}
if (SERVER_SECRET.length < 24) {
  console.error("SERVER_SECRET must be at least 24 characters");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("railway") ? { rejectUnauthorized: false } : undefined
});

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

function normalizeCode(value) {
  return String(value || "").trim().toUpperCase().replace(/\s+/g, "");
}

function hashPin(pin, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(String(pin), salt, 64).toString("hex");
  return { salt, hash };
}

function verifyPin(pin, salt, expectedHash) {
  try {
    const actual = crypto.scryptSync(String(pin), salt, 64);
    const expected = Buffer.from(expectedHash, "hex");
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function signAdminToken() {
  return jwt.sign({ role: "admin" }, SERVER_SECRET, { expiresIn: "7d" });
}

function signClientToken(clientId) {
  return jwt.sign({ role: "client", clientId }, SERVER_SECRET, { expiresIn: "30d" });
}

function bearerToken(req) {
  const value = String(req.headers.authorization || "");
  if (!value.startsWith("Bearer ")) return "";
  return value.slice(7).trim();
}

function requireAdmin(req, res, next) {
  try {
    const payload = jwt.verify(bearerToken(req), SERVER_SECRET);
    if (payload.role !== "admin") throw new Error("wrong role");
    req.auth = payload;
    next();
  } catch {
    res.status(401).json({ error: "غير مصرح" });
  }
}

function requireClient(req, res, next) {
  try {
    const payload = jwt.verify(bearerToken(req), SERVER_SECRET);
    if (payload.role !== "client" || !payload.clientId) throw new Error("wrong role");
    req.auth = payload;
    next();
  } catch {
    res.status(401).json({ error: "غير مصرح" });
  }
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS clients (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      code TEXT NOT NULL UNIQUE,
      pin_salt TEXT NOT NULL,
      pin_hash TEXT NOT NULL,
      page_name TEXT,
      page_url TEXT,
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused')),
      subscription_start DATE,
      subscription_end DATE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reports (
      id BIGSERIAL PRIMARY KEY,
      client_id BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      period_start DATE,
      period_end DATE,
      reach BIGINT,
      messages BIGINT,
      results BIGINT,
      followers BIGINT,
      engagement NUMERIC(10,2),
      best_post TEXT,
      recommendations TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id BIGSERIAL PRIMARY KEY,
      client_id BIGINT REFERENCES clients(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_reports_client_created
      ON reports(client_id, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_notifications_client_created
      ON notifications(client_id, created_at DESC);
  `);
}

function safeInt(value) {
  if (value === "" || value === null || value === undefined) return null;
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  return Math.trunc(n);
}

function safeNumber(value) {
  if (value === "" || value === null || value === undefined) return null;
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return null;
  return n;
}

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch {
    res.status(503).json({ ok: false });
  }
});

app.post("/api/admin/login", (req, res) => {
  const pin = String(req.body.pin || "");
  const a = Buffer.from(pin);
  const b = Buffer.from(ADMIN_PIN);
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!ok) return res.status(401).json({ error: "PIN غير صحيح" });
  res.json({ token: signAdminToken() });
});

app.get("/api/admin/clients", requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT
      c.*,
      CASE
        WHEN c.status = 'active'
          AND c.subscription_end IS NOT NULL
          AND c.subscription_end >= CURRENT_DATE
        THEN TRUE ELSE FALSE
      END AS subscription_active,
      (
        SELECT COUNT(*)::int
        FROM reports r
        WHERE r.client_id = c.id
      ) AS reports_count
    FROM clients c
    ORDER BY c.created_at DESC
  `);
  res.json(rows);
});

app.post("/api/admin/clients", requireAdmin, async (req, res) => {
  const name = String(req.body.name || "").trim();
  const code = normalizeCode(req.body.code);
  const pin = String(req.body.pin || "").trim();
  const pageName = String(req.body.page_name || "").trim() || null;
  const pageUrl = String(req.body.page_url || "").trim() || null;
  const start = String(req.body.subscription_start || "").trim() || null;
  const end = String(req.body.subscription_end || "").trim() || null;

  if (!name || !code || pin.length < 4) {
    return res.status(400).json({ error: "الاسم والكود وPIN من 4 أرقام على الأقل مطلوبين" });
  }

  const { salt, hash } = hashPin(pin);

  try {
    const { rows } = await pool.query(`
      INSERT INTO clients
        (name, code, pin_salt, pin_hash, page_name, page_url, subscription_start, subscription_end)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING id, name, code, page_name, page_url, status, subscription_start, subscription_end, created_at
    `, [name, code, salt, hash, pageName, pageUrl, start, end]);
    res.status(201).json(rows[0]);
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "كود العميل مستخدم بالفعل" });
    }
    console.error(error);
    res.status(500).json({ error: "تعذر إضافة العميل" });
  }
});

app.post("/api/admin/clients/:id/renew", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const days = Number(req.body.days);
  if (!Number.isInteger(id) || ![30, 90, 365].includes(days)) {
    return res.status(400).json({ error: "بيانات التجديد غير صحيحة" });
  }

  const { rows } = await pool.query(`
    UPDATE clients
    SET
      status = 'active',
      subscription_start = COALESCE(subscription_start, CURRENT_DATE),
      subscription_end =
        GREATEST(COALESCE(subscription_end, CURRENT_DATE), CURRENT_DATE)
        + ($2::text || ' days')::interval
    WHERE id = $1
    RETURNING id, name, code, status, subscription_start, subscription_end
  `, [id, days]);

  if (!rows[0]) return res.status(404).json({ error: "العميل غير موجود" });
  res.json(rows[0]);
});

app.post("/api/admin/clients/:id/status", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const status = String(req.body.status || "");
  if (!["active", "paused"].includes(status)) {
    return res.status(400).json({ error: "الحالة غير صحيحة" });
  }
  const { rows } = await pool.query(
    `UPDATE clients SET status=$2 WHERE id=$1 RETURNING id,name,code,status`,
    [id, status]
  );
  if (!rows[0]) return res.status(404).json({ error: "العميل غير موجود" });
  res.json(rows[0]);
});

app.post("/api/admin/clients/:id/report", requireAdmin, async (req, res) => {
  const clientId = Number(req.params.id);
  if (!Number.isInteger(clientId)) {
    return res.status(400).json({ error: "رقم العميل غير صحيح" });
  }

  const payload = {
    periodStart: String(req.body.period_start || "").trim() || null,
    periodEnd: String(req.body.period_end || "").trim() || null,
    reach: safeInt(req.body.reach),
    messages: safeInt(req.body.messages),
    results: safeInt(req.body.results),
    followers: safeInt(req.body.followers),
    engagement: safeNumber(req.body.engagement),
    bestPost: String(req.body.best_post || "").trim() || null,
    recommendations: String(req.body.recommendations || "").trim() || null
  };

  const exists = await pool.query("SELECT 1 FROM clients WHERE id=$1", [clientId]);
  if (!exists.rowCount) return res.status(404).json({ error: "العميل غير موجود" });

  const { rows } = await pool.query(`
    INSERT INTO reports
      (client_id, period_start, period_end, reach, messages, results, followers, engagement, best_post, recommendations)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    RETURNING *
  `, [
    clientId,
    payload.periodStart,
    payload.periodEnd,
    payload.reach,
    payload.messages,
    payload.results,
    payload.followers,
    payload.engagement,
    payload.bestPost,
    payload.recommendations
  ]);

  res.status(201).json(rows[0]);
});

app.post("/api/admin/clients/:id/notification", requireAdmin, async (req, res) => {
  const clientId = Number(req.params.id);
  const title = String(req.body.title || "").trim();
  const body = String(req.body.body || "").trim();
  if (!title || !body) return res.status(400).json({ error: "العنوان والرسالة مطلوبان" });

  const { rows } = await pool.query(`
    INSERT INTO notifications (client_id, title, body)
    VALUES ($1,$2,$3)
    RETURNING *
  `, [clientId, title, body]);

  res.status(201).json(rows[0]);
});

app.post("/api/admin/notifications/broadcast", requireAdmin, async (req, res) => {
  const title = String(req.body.title || "").trim();
  const body = String(req.body.body || "").trim();
  if (!title || !body) return res.status(400).json({ error: "العنوان والرسالة مطلوبان" });

  const { rows } = await pool.query(`
    INSERT INTO notifications (client_id, title, body)
    VALUES (NULL,$1,$2)
    RETURNING *
  `, [title, body]);

  res.status(201).json(rows[0]);
});

app.post("/api/client/login", async (req, res) => {
  const code = normalizeCode(req.body.code);
  const pin = String(req.body.pin || "").trim();

  const { rows } = await pool.query(`
    SELECT id, name, code, pin_salt, pin_hash, status, subscription_end
    FROM clients
    WHERE code=$1
    LIMIT 1
  `, [code]);

  const client = rows[0];
  if (!client || !verifyPin(pin, client.pin_salt, client.pin_hash)) {
    return res.status(401).json({ error: "الكود أو PIN غير صحيح" });
  }

  res.json({ token: signClientToken(client.id) });
});

app.get("/api/client/me", requireClient, async (req, res) => {
  const clientId = Number(req.auth.clientId);

  const { rows: clientRows } = await pool.query(`
    SELECT
      id, name, code, page_name, page_url, status, subscription_start, subscription_end, created_at,
      CASE
        WHEN status='active'
          AND subscription_end IS NOT NULL
          AND subscription_end >= CURRENT_DATE
        THEN TRUE ELSE FALSE
      END AS subscription_active
    FROM clients
    WHERE id=$1
  `, [clientId]);

  const client = clientRows[0];
  if (!client) return res.status(404).json({ error: "الحساب غير موجود" });

  const { rows: notifications } = await pool.query(`
    SELECT id, title, body, created_at
    FROM notifications
    WHERE client_id IS NULL OR client_id=$1
    ORDER BY created_at DESC
    LIMIT 100
  `, [clientId]);

  let reports = [];
  if (client.subscription_active) {
    const result = await pool.query(`
      SELECT
        id, period_start, period_end, reach, messages, results,
        followers, engagement, best_post, recommendations, created_at
      FROM reports
      WHERE client_id=$1
      ORDER BY created_at DESC
      LIMIT 100
    `, [clientId]);
    reports = result.rows;
  }

  res.json({
    client,
    latest_report: reports[0] || null,
    reports,
    notifications
  });
});

const ADMIN_HTML = `<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Marketing Manager Admin</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f5f7fb;margin:0;color:#1f2937}
    header{background:#0f6cbd;color:#fff;padding:18px;font-size:22px;font-weight:700}
    main{max-width:1100px;margin:auto;padding:16px}
    .card{background:#fff;border-radius:14px;padding:16px;margin:12px 0;box-shadow:0 2px 12px #0001}
    input,textarea,select,button{font:inherit;padding:10px;border-radius:9px;border:1px solid #d1d5db;box-sizing:border-box}
    input,textarea,select{width:100%;margin:5px 0 10px}
    button{background:#0f6cbd;color:#fff;border:0;cursor:pointer;margin:4px}
    button.gray{background:#6b7280}.danger{background:#b42318}.ok{color:#08783f;font-weight:700}.bad{color:#b42318;font-weight:700}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}
    .client{border:1px solid #e5e7eb;border-radius:12px;padding:12px;margin-top:10px}
    small{color:#6b7280}
  </style>
</head>
<body>
<header>Marketing Manager — الإدارة</header>
<main>
  <div class="card" id="loginBox">
    <h3>دخول الإدارة</h3>
    <input id="adminPin" type="password" placeholder="Admin PIN">
    <button onclick="adminLogin()">دخول</button>
    <div id="loginMsg"></div>
  </div>

  <div id="appBox" style="display:none">
    <div class="card">
      <h3>إضافة عميل</h3>
      <div class="grid">
        <input id="cName" placeholder="اسم العميل">
        <input id="cCode" placeholder="كود العميل مثال ABC123">
        <input id="cPin" type="password" placeholder="PIN للعميل">
        <input id="cPageName" placeholder="اسم الصفحة">
        <input id="cPageUrl" placeholder="رابط الصفحة">
        <input id="cStart" type="date">
        <input id="cEnd" type="date">
      </div>
      <button onclick="addClient()">إضافة العميل</button>
    </div>

    <div class="card">
      <h3>إرسال إشعار عام</h3>
      <input id="bTitle" placeholder="العنوان">
      <textarea id="bBody" placeholder="الرسالة"></textarea>
      <button onclick="broadcast()">إرسال للجميع</button>
    </div>

    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px">
        <h3>العملاء</h3>
        <button class="gray" onclick="loadClients()">تحديث</button>
      </div>
      <div id="clients"></div>
    </div>
  </div>
</main>
<script>
let token = localStorage.getItem("adminToken") || "";

async function api(url, options={}) {
  options.headers = Object.assign(
    {"Content-Type":"application/json"},
    options.headers || {},
    token ? {"Authorization":"Bearer " + token} : {}
  );
  const r = await fetch(url, options);
  const data = await r.json().catch(()=>({}));
  if (!r.ok) throw new Error(data.error || "حدث خطأ");
  return data;
}

async function adminLogin(){
  try{
    const pin=document.getElementById("adminPin").value;
    const data=await api("/api/admin/login",{method:"POST",body:JSON.stringify({pin})});
    token=data.token; localStorage.setItem("adminToken",token);
    showApp();
  }catch(e){document.getElementById("loginMsg").textContent=e.message}
}

function showApp(){
  document.getElementById("loginBox").style.display="none";
  document.getElementById("appBox").style.display="block";
  loadClients();
}

async function addClient(){
  try{
    const body={
      name:cName.value, code:cCode.value, pin:cPin.value,
      page_name:cPageName.value, page_url:cPageUrl.value,
      subscription_start:cStart.value, subscription_end:cEnd.value
    };
    await api("/api/admin/clients",{method:"POST",body:JSON.stringify(body)});
    alert("تمت إضافة العميل"); loadClients();
  }catch(e){alert(e.message)}
}

async function renew(id,days){
  try{
    await api("/api/admin/clients/"+id+"/renew",{method:"POST",body:JSON.stringify({days})});
    loadClients();
  }catch(e){alert(e.message)}
}

async function toggleStatus(id,current){
  const status=current==="active"?"paused":"active";
  try{
    await api("/api/admin/clients/"+id+"/status",{method:"POST",body:JSON.stringify({status})});
    loadClients();
  }catch(e){alert(e.message)}
}

async function addReport(id){
  const period_start=prompt("من تاريخ YYYY-MM-DD")||"";
  const period_end=prompt("إلى تاريخ YYYY-MM-DD")||"";
  const reach=prompt("الوصول - اتركه فارغ لو غير متاح")||"";
  const messages=prompt("عدد الرسائل - اتركه فارغ لو غير متاح")||"";
  const results=prompt("النتائج - اتركه فارغ لو غير متاح")||"";
  const followers=prompt("المتابعون - اتركه فارغ لو غير متاح")||"";
  const engagement=prompt("نسبة/رقم التفاعل - اتركه فارغ لو غير متاح")||"";
  const best_post=prompt("أفضل بوست")||"";
  const recommendations=prompt("التوصيات")||"";
  try{
    await api("/api/admin/clients/"+id+"/report",{method:"POST",body:JSON.stringify({
      period_start,period_end,reach,messages,results,followers,engagement,best_post,recommendations
    })});
    alert("تم حفظ التقرير");
    loadClients();
  }catch(e){alert(e.message)}
}

async function notifyClient(id){
  const title=prompt("عنوان الإشعار")||"";
  const body=prompt("نص الإشعار")||"";
  if(!title||!body)return;
  try{
    await api("/api/admin/clients/"+id+"/notification",{method:"POST",body:JSON.stringify({title,body})});
    alert("تم حفظ الإشعار");
  }catch(e){alert(e.message)}
}

async function broadcast(){
  try{
    await api("/api/admin/notifications/broadcast",{method:"POST",body:JSON.stringify({title:bTitle.value,body:bBody.value})});
    alert("تم إرسال الإشعار العام");
    bTitle.value="";bBody.value="";
  }catch(e){alert(e.message)}
}

async function loadClients(){
  try{
    const list=await api("/api/admin/clients");
    clients.innerHTML=list.map(c=>\`
      <div class="client">
        <b>\${esc(c.name)}</b> — <code>\${esc(c.code)}</code><br>
        <small>\${esc(c.page_name||"بدون اسم صفحة")}</small><br>
        الاشتراك: <span class="\${c.subscription_active?"ok":"bad"}">\${c.subscription_active?"ساري":"منتهي/موقوف"}</span><br>
        من: \${c.subscription_start||"-"} — إلى: \${c.subscription_end||"-"}<br>
        التقارير: \${c.reports_count}
        <div>
          <button onclick="renew(\${c.id},30)">+30 يوم</button>
          <button onclick="renew(\${c.id},90)">+90 يوم</button>
          <button onclick="renew(\${c.id},365)">+365 يوم</button>
          <button onclick="addReport(\${c.id})">إضافة تقرير</button>
          <button onclick="notifyClient(\${c.id})">إشعار</button>
          <button class="gray" onclick="toggleStatus(\${c.id},'\${c.status}')">\${c.status==="active"?"إيقاف":"تفعيل"}</button>
        </div>
      </div>
    \`).join("") || "لا يوجد عملاء";
  }catch(e){
    if(e.message==="غير مصرح"){localStorage.removeItem("adminToken");location.reload()}
    else clients.textContent=e.message;
  }
}

function esc(v){
  return String(v??"").replace(/[&<>"']/g, m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]));
}

if(token) showApp();
</script>
</body>
</html>`;

const CLIENT_HTML = `<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Marketing Manager Client</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f5f7fb;margin:0;color:#1f2937}
    header{background:#1e8e3e;color:#fff;padding:18px;font-size:22px;font-weight:700}
    main{max-width:900px;margin:auto;padding:16px}
    .card{background:#fff;border-radius:14px;padding:16px;margin:12px 0;box-shadow:0 2px 12px #0001}
    input,button{font:inherit;padding:11px;border-radius:9px;border:1px solid #d1d5db;box-sizing:border-box}
    input{width:100%;margin:6px 0 10px}
    button{background:#1e8e3e;color:#fff;border:0;cursor:pointer}
    .ok{color:#08783f;font-weight:700}.bad{color:#b42318;font-weight:700}
    .metric{display:inline-block;background:#eef6ef;border-radius:10px;padding:10px;margin:4px}
    .note{border-bottom:1px solid #eee;padding:10px 0}
    small{color:#6b7280}
  </style>
</head>
<body>
<header>Marketing Manager — العميل</header>
<main>
  <div class="card" id="loginBox">
    <h3>تسجيل الدخول</h3>
    <input id="code" placeholder="كود العميل">
    <input id="pin" type="password" placeholder="PIN">
    <button onclick="clientLogin()">دخول</button>
    <div id="loginMsg"></div>
  </div>

  <div id="appBox" style="display:none">
    <div class="card" id="profile"></div>
    <div class="card" id="latest"></div>
    <div class="card">
      <h3>أرشيف التقارير</h3>
      <div id="reports"></div>
    </div>
    <div class="card">
      <h3>الإشعارات</h3>
      <div id="notifications"></div>
    </div>
    <button onclick="logout()">تسجيل خروج</button>
  </div>
</main>
<script>
let token=localStorage.getItem("clientToken")||"";

async function api(url,options={}){
  options.headers=Object.assign(
    {"Content-Type":"application/json"},
    options.headers||{},
    token?{"Authorization":"Bearer "+token}:{}
  );
  const r=await fetch(url,options);
  const data=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(data.error||"حدث خطأ");
  return data;
}

async function clientLogin(){
  try{
    const data=await api("/api/client/login",{method:"POST",body:JSON.stringify({code:code.value,pin:pin.value})});
    token=data.token;localStorage.setItem("clientToken",token);showApp();
  }catch(e){loginMsg.textContent=e.message}
}

async function showApp(){
  loginBox.style.display="none";appBox.style.display="block";
  try{
    const d=await api("/api/client/me");
    const c=d.client;
    profile.innerHTML=\`
      <h3>\${esc(c.name)}</h3>
      <div>\${esc(c.page_name||"")}</div>
      <div>حالة الاشتراك: <span class="\${c.subscription_active?"ok":"bad"}">\${c.subscription_active?"ساري":"منتهي/موقوف"}</span></div>
      <div>ينتهي في: \${c.subscription_end||"-"}</div>
    \`;

    if(!c.subscription_active){
      latest.innerHTML="<h3>التقارير</h3><div class='bad'>الاشتراك غير ساري. التقارير المدفوعة متوقفة حتى التجديد.</div>";
      reports.innerHTML="";
    }else if(d.latest_report){
      latest.innerHTML=reportHtml(d.latest_report,true);
      reports.innerHTML=d.reports.map(r=>reportHtml(r,false)).join("");
    }else{
      latest.innerHTML="<h3>آخر تقرير</h3><div>لا يوجد تقرير مسجل حتى الآن.</div>";
      reports.innerHTML="لا توجد تقارير";
    }

    notifications.innerHTML=d.notifications.map(n=>\`
      <div class="note"><b>\${esc(n.title)}</b><br>\${esc(n.body)}<br><small>\${fmt(n.created_at)}</small></div>
    \`).join("")||"لا توجد إشعارات";
  }catch(e){
    if(e.message==="غير مصرح")logout(); else alert(e.message);
  }
}

function reportHtml(r,latestFlag){
  return \`
    <div class="note">
      <h3>\${latestFlag?"آخر تقرير":"تقرير"}</h3>
      <small>\${r.period_start||"-"} إلى \${r.period_end||"-"}</small><br>
      \${metric("الوصول",r.reach)}
      \${metric("الرسائل",r.messages)}
      \${metric("النتائج",r.results)}
      \${metric("المتابعون",r.followers)}
      \${metric("التفاعل",r.engagement)}
      <p><b>أفضل بوست:</b> \${esc(r.best_post||"-")}</p>
      <p><b>التوصيات:</b> \${esc(r.recommendations||"-")}</p>
    </div>
  \`;
}

function metric(label,value){
  if(value===null||value===undefined)return "";
  return \`<span class="metric"><b>\${label}</b>: \${esc(value)}</span>\`;
}

function fmt(v){try{return new Date(v).toLocaleString("ar-EG")}catch{return v||""}}
function esc(v){return String(v??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]))}
function logout(){localStorage.removeItem("clientToken");location.reload()}
if(token)showApp();
</script>
</body>
</html>`;

app.get("/", (req, res) => res.redirect("/client/"));
app.get("/admin", (req, res) => res.redirect("/admin/"));
app.get("/client", (req, res) => res.redirect("/client/"));
app.get("/admin/", (req, res) => res.type("html").send(ADMIN_HTML));
app.get("/client/", (req, res) => res.type("html").send(CLIENT_HTML));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "خطأ داخلي في السيرفر" });
});

initDb()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Marketing Manager backend listening on port ${PORT}`);
    });
app.get("/", (req, res) => res.type("html").send(CLIENT_HTML));
app.get("/admin", (req, res) => res.type("html").send(ADMIN_HTML));
app.get("/admin/", (req, res) => res.type("html").send(ADMIN_HTML));
app.get("/client", (req, res) => res.type("html").send(CLIENT_HTML));
app.get("/client/", (req, res) => res.type("html").send(CLIENT_HTML));
