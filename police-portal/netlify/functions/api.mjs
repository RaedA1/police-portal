import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const DEPTS = { academy: ["Academy", true], affairs: ["Affairs", true], wings: ["Wings", false] };
const J = (o, s = 200, x = {}) => new Response(JSON.stringify(o), {
  status: s,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", ...x },
});
const sha = v => crypto.createHash("sha256").update(String(v)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const sign = (p, k) => crypto.createHmac("sha256", k).update(p).digest("base64url");
const LOCK_SEC = 180;
const COOKIE = "HttpOnly; Secure; SameSite=Strict; Path=/";

function mint(k) {
  const c = crypto.randomBytes(16).toString("hex");
  const p = Buffer.from(JSON.stringify({ e: Date.now() + 2 * 3600e3, c })).toString("base64url");
  return { tok: p + "." + sign(p, k), c };
}
function session(req, k) {
  const m = /(?:^|;\s*)sid=([\w-]+\.[\w-]+)/.exec(req.headers.get("cookie") || "");
  if (!k || !m) return null;
  const [p, s] = m[1].split(".");
  if (!same(sign(p, k), s)) return null;
  try { const o = JSON.parse(Buffer.from(p, "base64url").toString()); return o.e > Date.now() ? o : null; } catch { return null; }
}
const originOk = req => {
  const o = req.headers.get("origin");
  if (!o) return true;
  try { return new URL(o).host === new URL(req.url).host; } catch { return false; }
};
async function body(req, max) {
  if (!(req.headers.get("content-type") || "").includes("application/json")) throw new Error("type");
  const t = await req.text();
  if (t.length > max) throw new Error("size");
  return JSON.parse(t);
}
async function log(st, a) {
  const l = (await st.get("audit", { type: "json" })) || [];
  l.unshift({ t: new Date().toISOString(), a });
  await st.setJSON("audit", l.slice(0, 100));
}

/* ---- strict server-side validation (the browser is never trusted) ---- */
const cl = (s, n = 80) => String(s ?? "").replace(/[\u0000-\u001f<>]/g, "").trim().slice(0, n);
const num = x => { x = Number(x); if (!Number.isInteger(x) || x < 0 || x > 999) throw new Error("bad"); return x; };
const LRE = /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+\/=]+$/;
function cleanProto(p) {
  return { sections: (Array.isArray(p?.sections) ? p.sections : []).slice(0, 12).map((s, i) => ({
    id: /^[a-z0-9]{1,16}$/i.test(s?.id) ? s.id : "s" + i, t: cl(s?.t, 60), note: cl(s?.note, 200),
    rows: (Array.isArray(s?.rows) ? s.rows : []).slice(0, 80).map(r => ({ a: cl(r?.a, 40), b: cl(r?.b, 60), c: cl(r?.c, 120) })).filter(r => r.a || r.b || r.c),
  })).filter(s => s.t) };
}
function cleanWanted(w) {
  return (Array.isArray(w) ? w : []).slice(0, 40).map(x => ({
    id: /^[a-z0-9]{1,16}$/i.test(x?.id) ? x.id : "w" + Math.random().toString(36).slice(2, 10),
    n: cl(x?.n, 60), j: cl(x?.j, 60), d: cl(x?.d, 600), s: x?.s === "arrested" ? "arrested" : "wanted", k: ["low", "medium", "high"].includes(x?.k) ? x.k : "", l: cl(x?.l, 80), r: cl(x?.r, 40),
    img: typeof x?.img === "string" && x.img.length <= 70000 && LRE.test(x.img) ? x.img : "",
  })).filter(x => x.n);
}
const clL = (s, n) => String(s ?? "").replace(/[\u0000-\u0009\u000b-\u001f<>]/g, "").trim().slice(0, n);
const okImg = (x, m) => typeof x === "string" && x.length <= m && LRE.test(x) ? x : "";
function cleanCards(arr, f) {
  return (Array.isArray(arr) ? arr : []).slice(0, 30).map(x => ({
    id: /^[a-z0-9]{1,16}$/i.test(x?.id) ? x.id : "c" + Math.random().toString(36).slice(2, 10),
    n: cl(x?.n, 60), pid: okId(x?.pid), [f]: cl(x?.[f], 60), img: okImg(x?.img, 150000),
  })).filter(x => x.n);
}
function cleanRT(o) {
  const r = {};
  for (const [k, v] of Object.entries(o).slice(0, 80)) { const kk = cl(k, 40), vv = cl(v, 40); if (kk && vv) r[kk] = vv; }
  return r;
}
const okId = x => typeof x === "string" && /^[a-z0-9]{1,16}$/i.test(x) ? x : "";
const cleanCustom = arr => (Array.isArray(arr) ? arr : []).slice(0, 8).map(g => ({
  t: cl(g?.t, 40),
  list: (Array.isArray(g?.list) ? g.list : []).slice(0, 12).map(m => ({ n: cl(m?.n), u: cl(m?.u), id: okId(m?.id) })),
})).filter(g => g.t);
function cleanPerm(p) {
  const cols = (Array.isArray(p?.cols) ? p.cols : []).slice(0, 16).map(x => cl(x, 40) || "—");
  return {
    cols,
    rows: (Array.isArray(p?.rows) ? p.rows : []).slice(0, 30).map(r => ({ r: cl(r?.r, 40), all: clL(r?.all, 400), c: cols.map((_, i) => (r?.c?.[i] ? 1 : 0)) })).filter(r => r.r),
    details: (Array.isArray(p?.details) ? p.details : []).slice(0, 30).map(d => ({ t: cl(d?.t, 60), d: clL(d?.d, 800) })).filter(d => d.t),
  };
}
function cleanItems(arr) {
  return (Array.isArray(arr) ? arr : []).slice(0, 80).map(x => ({
    id: /^[a-z0-9]{1,16}$/i.test(x?.id) ? x.id : "i" + Math.random().toString(36).slice(2, 10),
    lv: [1, 2, 3].includes(+x?.lv) ? +x.lv : 1, n: cl(x?.n, 60),
    ty: ["legal", "semi", "illegal"].includes(x?.ty) ? x.ty : "semi", c: clL(x?.c, 300), img: okImg(x?.img, 60000),
  })).filter(x => x.n);
}
function cleanTxt(o) {
  const r = {};
  for (const [k, v] of Object.entries(o).slice(0, 500)) {
    const kk = cl(k, 300);
    if (!kk || ["__proto__", "constructor", "prototype"].includes(kk)) continue;
    const e = cl(v?.e, 300), a = cl(v?.a, 300);
    if (e || a) r[kk] = { e, a };
  }
  return r;
}
const SECK = ["articles", "fines", "outfits"];
function cleanSecs(o) {
  const out = {};
  for (const k of SECK) {
    const s = o?.[k]; if (!s) continue;
    out[k] = { v: Math.min(Math.max(+s.v | 0, 0), 99), sections: (Array.isArray(s.sections) ? s.sections : []).slice(0, 40).map((x, i) => ({
      id: /^[a-z0-9]{1,16}$/i.test(x?.id) ? x.id : "s" + i, t: cl(x?.t, 80), g: x?.g === "w" ? "w" : "",
      rows: (Array.isArray(x?.rows) ? x.rows : []).slice(0, 150).map(r => { const q = {}; for (const f of "abcde") q[f] = cl(r?.[f], 200); return q; }).filter(r => "abcde".split("").some(f => r[f])),
    })).filter(x => x.t) };
  }
  return out;
}
function cleanRoster(r) {
  const rk = [...new Set((Array.isArray(r?.ranks) ? r.ranks : []).map(x => cl(x, 40)).filter(Boolean))];
  const seen = new Set(), people = [];
  for (const p of (Array.isArray(r?.people) ? r.people : []).slice(0, 1000)) {
    const u = cl(p?.u, 16), rank = cl(p?.r, 40);
    if (!u || !rank) continue;
    let id = typeof p?.id === "string" && /^[a-z0-9]{1,16}$/i.test(p.id) ? p.id : "";
    if (!id || seen.has(id)) id = "p" + Math.random().toString(36).slice(2, 12);
    seen.add(id); people.push({ id, u, n: cl(p?.n, 60), r: rank });
    if (!rk.includes(rank)) rk.push(rank);
  }
  const ranks = rk.slice(0, 60), logos = {};
  for (const k of ranks) { const v = r?.logos?.[k]; if (typeof v === "string" && v.length <= 60000 && LRE.test(v)) logos[k] = v; }
  return { ranks, people, logos };
}
function sanitize(v) {
  if (!v || !Array.isArray(v.ranks) || !Array.isArray(v.wings) || !v.depts || typeof v.depts !== "object") throw new Error("bad");
  const wings = [...new Set(v.wings.map(w => cl(w)).filter(w => w && w !== "*"))].slice(0, 30);
  const ranks = v.ranks.slice(0, 30).map(r => ({
    name: cl(r?.name), mdt: num(r?.mdt), dispatch: num(r?.dispatch), presence: num(r?.presence), shift: num(r?.shift),
    shiftDone: r?.shiftDone ? 1 : 0, active: r?.active ? 1 : 0,
    wings: (Array.isArray(r?.wings) ? r.wings : []).map(w => cl(w)).filter(w => w === "*" || wings.includes(w)),
  }));
  if (!ranks.length || ranks.some(r => !r.name) || new Set(ranks.map(r => r.name.toLowerCase())).size !== ranks.length) throw new Error("bad");
  const depts = {};
  for (const [k, d0] of Object.entries(v.depts).slice(0, 12)) {
    if (!/^[a-z0-9_]{1,24}$/.test(k)) continue;
    const d = d0 || {}, b = DEPTS[k], mg = b ? b[1] : !!d.mg;
    const o = { title: b ? b[0] : (cl(d.title, 40) || cl(d.titleAr, 40) || "Department"), mg: mg ? 1 : 0 };
    for (const f of ["cmd", "cmdUnit", "dep", "depUnit"]) o[f] = cl(d[f]);
    o.cmdId = okId(d.cmdId); o.depId = okId(d.depId); o.custom = cleanCustom(d.custom);
    o.roles = [0, 1, 2].map(i => cl(d.roles?.[i], 40));
    if (!b) {
      o.titleAr = cl(d.titleAr, 40); o.descAr = cl(d.descAr, 120);
      o.desc = cl(d.desc, 120);
      o.color = /^#[0-9a-f]{6}$/i.test(d.color) ? d.color : "#e8cf55";
      o.roles = [0, 1, 2].map(i => cl(d.roles?.[i], 40));
      o.logo = typeof d.logo === "string" && d.logo.length <= 150000 && /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+\/=]+$/.test(d.logo) ? d.logo : "";
    }
    o.mgmtList = mg ? (Array.isArray(d.mgmtList) && d.mgmtList.length ? d.mgmtList : [{}]).slice(0, 12).map(m => ({ n: cl(m?.n), u: cl(m?.u), id: okId(m?.id) })) : [];
    depts[k] = o;
  }
  const news = (Array.isArray(v.news) ? v.news : []).slice(0, 20).map(n => ({ t: cl(n?.t), b: clL(n?.b, 2000), d: cl(n?.d, 20), img: okImg(n?.img, 150000) })).filter(n => n.t);
  return { wings, ranks, depts, news, roster: v.roster ? cleanRoster(v.roster) : undefined, proto: v.proto ? cleanProto(v.proto) : undefined, wanted: Array.isArray(v.wanted) ? cleanWanted(v.wanted) : undefined, secs: v.secs ? cleanSecs(v.secs) : undefined, txt: v.txt && typeof v.txt === "object" && !Array.isArray(v.txt) ? cleanTxt(v.txt) : undefined, perm: v.perm && typeof v.perm === "object" && Array.isArray(v.perm.cols) ? cleanPerm(v.perm) : undefined, items: Array.isArray(v.items) ? cleanItems(v.items) : undefined, rtitles: v.rtitles && typeof v.rtitles === "object" && !Array.isArray(v.rtitles) ? cleanRT(v.rtitles) : undefined, cmds: Array.isArray(v.cmds) ? cleanCards(v.cmds, "t") : undefined, cars: Array.isArray(v.cars) ? cleanCards(v.cars, "r") : undefined, updated: Date.now() };
}

export default async (req, ctx) => {
  try {
    const sec = process.env.SESSION_SECRET, pw = process.env.ADMIN_PASSWORD;
    const st = getStore({ name: "portal", consistency: "strong" });
    const path = new URL(req.url).pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
    const m = req.method;
    if (m !== "GET" && !originOk(req)) return J({ error: "forbidden" }, 403);

    if (m === "GET" && path === "data") return J({ data: (await st.get("data", { type: "json" })) || null });
    if (m === "GET" && path === "session") { const s = session(req, sec); return J(s ? { admin: true, csrf: s.c } : { admin: false }); }
    if (m === "POST" && path === "logout") return J({ ok: true }, 200, { "set-cookie": `sid=; ${COOKIE}; Max-Age=0` });

    if (m === "POST" && path === "login") {
      if (!sec || !pw) return J({ error: "server not configured" }, 500);
      const ip = ctx?.ip || req.headers.get("x-nf-client-connection-ip") || "0";
      const rk = "rl-" + sha(ip).toString("hex").slice(0, 24);
      const rl = (await st.get(rk, { type: "json" })) || { n: 0, u: 0 };
      if (rl.u > Date.now()) {
        const left = Math.ceil((rl.u - Date.now()) / 1000);
        return J({ error: "limited", retryAfter: left }, 429, { "retry-after": String(left) });
      }
      if (rl.u) { rl.n = 0; rl.u = 0; }
      let b; try { b = await body(req, 2000); } catch { return J({ error: "invalid" }, 400); }
      if (typeof b.password === "string" && same(b.password, pw)) {
        await st.delete(rk);
        const s = mint(sec);
        await log(st, "Admin signed in");
        return J({ ok: true, csrf: s.c }, 200, { "set-cookie": `sid=${s.tok}; ${COOKIE}; Max-Age=7200` });
      }
      rl.n++;
      const locked = rl.n >= 5;
      if (locked) rl.u = Date.now() + LOCK_SEC * 1000;
      await st.setJSON(rk, rl);
      await new Promise(r => setTimeout(r, 400));
      return locked ? J({ error: "limited", retryAfter: LOCK_SEC }, 429, { "retry-after": String(LOCK_SEC) }) : J({ error: "denied" }, 401);
    }

    /* everything below requires a valid admin session */
    const s = session(req, sec);
    if (!s) return J({ error: "unauthorized" }, 401);
    if (m === "GET" && path === "audit") return J({ log: (await st.get("audit", { type: "json" })) || [] });
    if (m === "PUT" && path === "data") {
      if (!same(req.headers.get("x-csrf") || "", s.c)) return J({ error: "forbidden" }, 403);
      let next; try { next = sanitize(await body(req, 5500000)); } catch { return J({ error: "invalid data" }, 400); }
      const old = await st.get("data", { type: "json" });
      if (!next.roster && old?.roster) next.roster = old.roster;
      if (!next.proto && old?.proto) next.proto = old.proto;
      if (!next.wanted && old?.wanted) next.wanted = old.wanted;
      if (!next.cmds && old?.cmds) next.cmds = old.cmds;
      if (!next.cars && old?.cars) next.cars = old.cars;
      if (!next.rtitles && old?.rtitles) next.rtitles = old.rtitles;
      if (!next.perm && old?.perm) next.perm = old.perm;
      if (!next.txt && old?.txt) next.txt = old.txt;
      if (!next.items && old?.items) next.items = old.items;
      if (old?.secs || next.secs) next.secs = { ...(old?.secs || {}), ...(next.secs || {}) };
      const ch = ["wings", "ranks", "depts", "news", "roster", "proto", "wanted", "secs", "cmds", "cars", "rtitles", "perm", "items", "txt"].filter(k => JSON.stringify(old?.[k]) !== JSON.stringify(next[k]));
      await st.setJSON("data", next);
      if (ch.length) await log(st, "Updated: " + ch.join(", "));
      return J({ ok: true });
    }
    return J({ error: "not found" }, 404);
  } catch (e) {
    console.error(e);
    return J({ error: "server error" }, 500);
  }
};
export const config = { path: "/api/*" };
