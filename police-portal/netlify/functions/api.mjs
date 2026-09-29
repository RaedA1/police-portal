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
  for (const [k, [title, mg]] of Object.entries(DEPTS)) {
    const d = v.depts[k] || {};
    const o = { title };
    for (const f of ["cmd", "cmdUnit", "dep", "depUnit"]) o[f] = cl(d[f]);
    o.mgmtList = mg ? (Array.isArray(d.mgmtList) && d.mgmtList.length ? d.mgmtList : [{}]).slice(0, 12).map(m => ({ n: cl(m?.n), u: cl(m?.u) })) : [];
    depts[k] = o;
  }
  const news = (Array.isArray(v.news) ? v.news : []).slice(0, 20).map(n => ({ t: cl(n?.t), b: cl(n?.b, 300), d: cl(n?.d, 20) })).filter(n => n.t);
  return { wings, ranks, depts, news, updated: Date.now() };
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
      if (rl.u > Date.now()) return J({ error: "limited" }, 429);
      let b; try { b = await body(req, 2000); } catch { return J({ error: "invalid" }, 400); }
      if (typeof b.password === "string" && same(b.password, pw)) {
        await st.delete(rk);
        const s = mint(sec);
        await log(st, "Admin signed in");
        return J({ ok: true, csrf: s.c }, 200, { "set-cookie": `sid=${s.tok}; ${COOKIE}; Max-Age=7200` });
      }
      rl.n++;
      if (rl.n >= 5) rl.u = Date.now() + Math.min(rl.n - 4, 15) * 60000;
      await st.setJSON(rk, rl);
      await new Promise(r => setTimeout(r, 400));
      return J({ error: "denied" }, 401);
    }

    /* everything below requires a valid admin session */
    const s = session(req, sec);
    if (!s) return J({ error: "unauthorized" }, 401);
    if (m === "GET" && path === "audit") return J({ log: (await st.get("audit", { type: "json" })) || [] });
    if (m === "PUT" && path === "data") {
      if (!same(req.headers.get("x-csrf") || "", s.c)) return J({ error: "forbidden" }, 403);
      let next; try { next = sanitize(await body(req, 300000)); } catch { return J({ error: "invalid data" }, 400); }
      const old = await st.get("data", { type: "json" });
      const ch = ["wings", "ranks", "depts", "news"].filter(k => JSON.stringify(old?.[k]) !== JSON.stringify(next[k]));
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
