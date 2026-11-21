// PureBite — Cloudflare Pages Worker (_worker.js)
// অর্ডার, কাস্টমার অ্যাকাউন্ট, কমিশন সদস্য, অ্যাডমিন API ও নোটিফিকেশন
// দরকারি: KV binding নাম "KV", Secret "ADMIN_KEY" (এবং ঐচ্ছিক RESEND_API_KEY, CALLMEBOT_KEY)

const H = { 'Cache-Control': 'no-store' };
const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Max-Age': '600' };
const J = (o, s = 200, cors = false) => Response.json(o, { status: s, headers: cors ? { ...H, ...CORS } : H });
const Z = [['ঢাকা সিটির ভেতরে', 60], ['ঢাকা সিটির বাইরে', 90], ['ঢাকা জেলার বাইরে', 110]];
const ST = ['new', 'packing', 'shipped', 'delivered', 'cancelled'];
const ST_BN = { 'নতুন': 'new', 'প্যাকিং': 'packing', 'পাঠানো হয়েছে': 'shipped', 'ডেলিভারি হয়েছে': 'delivered', 'বাতিল': 'cancelled' };
const normSt = (s) => (ST.includes(s) ? s : ST_BN[s] || 'new');
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const BD = /^01[3-9]\d{8}$/;
const EM = /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/;
const te = new TextEncoder();

// ---------- ক্রিপ্টো ----------
const b64u = (u8) => { let s = ''; for (const c of u8) s += String.fromCharCode(c); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const unb64u = (s) => { s = String(s).replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const r = atob(s); const u = new Uint8Array(r.length); for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i); return u; };
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
const rndStr = (n, al = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789') => Array.from(rnd(n), (x) => al[x % al.length]).join('');
const eq = (a, b) => { a = String(a); b = String(b); if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };
const sha = async (s) => b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(String(s)))));
async function pbkdf(pw, salt) {
  const k = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return b64u(new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, k, 256)));
}
async function mkPw(pw) { const salt = rnd(16); return { salt: b64u(salt), hash: await pbkdf(pw, salt) }; }
async function chkPw(pw, salt, hash) { if (!salt || !hash) return false; return eq(await pbkdf(String(pw), unb64u(salt)), hash); }
const hkey = (env) => crypto.subtle.importKey('raw', te.encode(env.TOKEN_SECRET || 'pb|' + env.ADMIN_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
const hsign = async (env, p) => b64u(new Uint8Array(await crypto.subtle.sign('HMAC', await hkey(env), te.encode(p))));
async function mkTok(env, u) {
  const p = b64u(te.encode(JSON.stringify({ u: u.id, v: u.pv || 0, e: Math.floor(Date.now() / 1000) + 60 * 86400 })));
  return p + '.' + (await hsign(env, p));
}
async function authUser(env, request) {
  const h = request.headers.get('Authorization') || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';
  const [p, sig] = t.split('.');
  if (!p || !sig || !(env.ADMIN_KEY || env.TOKEN_SECRET)) return null;
  if (!eq(await hsign(env, p), sig)) return null;
  let d;
  try { d = JSON.parse(new TextDecoder().decode(unb64u(p))); } catch (e) { return null; }
  if (!d || d.e < Date.now() / 1000) return null;
  const u = await getU(env, d.u);
  if (!u || (u.pv || 0) !== d.v) return null;
  return u;
}
async function hit(tag, ip, sec) {
  const k = new Request('https://rl.local/' + tag + '/' + encodeURIComponent(ip));
  if (await caches.default.match(k)) return true;
  await caches.default.put(k, new Response('1', { headers: { 'Cache-Control': 'max-age=' + sec } }));
  return false;
}

// ---------- ডেটা (KV) ----------
const getU = (env, id) => env.KV.get('U:' + id, 'json');
async function putU(env, u) {
  const meta = { n: String(u.name || '').slice(0, 30), p: u.phone || '', e: String(u.email || '').slice(0, 60), o: (u.orders || []).length, k: ((u.cart && u.cart.items) || []).length, q: u.pend ? 1 : 0, c: u.claimed ? 1 : 0, cm: (u.comm && u.comm.st) || 'none', t: u.created || 0 };
  await env.KV.put('U:' + u.id, JSON.stringify(u), { metadata: meta });
}
async function findU(env, ident) { if (!ident) return null; const id = await env.KV.get('X:' + ident); return id ? getU(env, id) : null; }
async function setIdx(env, u) { for (const k of [u.phone, u.email]) if (k) await env.KV.put('X:' + k, u.id); }
async function affU(env, code) { if (!code) return null; const id = await env.KV.get('AF:' + code); if (!id) return null; const u = await getU(env, id); return u && u.comm && u.comm.st === 'approved' ? u : null; }
async function getCfg(env) { return { rate: 10, wsPct: 10, wsNote: '', pp: {}, hide: [], ...((await env.KV.get('CFG', 'json')) || {}) }; }
const newUser = (o) => ({ id: rndStr(12, 'abcdefghijklmnopqrstuvwxyz0123456789'), name: '', phone: '', email: '', addr: '', created: Date.now(), claimed: false, pv: 0, orders: [], cart: { items: [], ts: 0 }, reads: [], comm: { st: 'none', orders: [] }, ...o });
function normIdent(s) {
  s = String(s || '').trim();
  if (s.includes('@')) return s.toLowerCase().slice(0, 80);
  return s.replace(/[০-৯]/g, (d) => '০১২৩৪৫৬৭৮৯'.indexOf(d)).replace(/[\s\-().]/g, '').replace(/^\+?88(?=01)/, '');
}
const identOk = (i) => (i.includes('@') ? EM.test(i) : BD.test(i));
const pwErr = (p) => {
  p = String(p || '');
  if (p.length < 8 || p.length > 64) return 'পাসওয়ার্ড ৮–৬৪ অক্ষরের হতে হবে';
  if (!/[a-z]/.test(p) || !/[A-Z]/.test(p) || !/\d/.test(p) || !/[^A-Za-z0-9]/.test(p)) return 'পাসওয়ার্ডে ছোট ও বড় হাতের ইংরেজি অক্ষর, সংখ্যা ও একটি চিহ্ন (@#$!) থাকতে হবে';
  return '';
};
const meOf = (u) => ({ name: u.name, phone: u.phone || '', email: u.email || '', addr: u.addr || '', hasPw: !!u.hash, claimed: !!u.claimed, created: u.created, orders: (u.orders || []).slice(0, 100), cart: u.cart || { items: [], ts: 0 }, reads: (u.reads || []).slice(0, 60), comm: { st: (u.comm && u.comm.st) || 'none' } });
function commStats(c) {
  let ok = 0, pend = 0, rj = 0, nOk = 0, nPend = 0, nRj = 0, earned = 0, pendComm = 0;
  for (const o of c.orders || []) {
    const cm = +o.c || 0;
    if (o.st === 'cancelled' || o.rj) { rj += o.b; nRj++; }
    else if (o.st === 'delivered') { ok += o.b; nOk++; earned += cm; }
    else { pend += o.b; nPend++; pendComm += cm; }
  }
  const paid = (+c.paid || 0) + (c.pays || []).reduce((a, x) => a + (+x.amt || 0), 0);
  return { ok, pend, rj, nOk, nPend, nRj, earned, paid, due: Math.max(0, earned - paid), pendComm, clicks: (c.ck && c.ck.t) || 0, today: c.ck && c.ck.d === today() ? c.ck.n : 0 };
}
const today = () => new Date(Date.now() + 6 * 3600 * 1000).toISOString().slice(0, 10);
const effPct = (cfg, name, rate) => {
  if ((cfg.hide || []).includes(name)) return 0;
  const v = cfg.pp && cfg.pp[name];
  return v == null || v === '' ? +rate || 0 : +v || 0;
};
function calcComm(cfg, items, sub, cd, rate) {
  if (sub <= 0) return 0;
  const f = (sub - cd) / sub;
  return Math.round(items.reduce((a, i) => a + (i.q * i.p * effPct(cfg, i.n, rate)) / 100, 0) * f);
}

// ---------- নোটিফিকেশন (WhatsApp + ইমেইল একসাথে) ----------
async function notifyOwner(env, text, subject, html) {
  const jobs = [];
  if (env.CALLMEBOT_KEY) {
    const ph = env.WA_PHONE || '+8801344628989';
    jobs.push(fetch(`https://api.callmebot.com/whatsapp.php?phone=${encodeURIComponent(ph)}&text=${encodeURIComponent(text)}&apikey=${encodeURIComponent(env.CALLMEBOT_KEY)}`).catch(() => {}));
  }
  if (env.RESEND_API_KEY) jobs.push(sendMail(env, env.NOTIFY_EMAIL || 'purebite16@gmail.com', subject, html || `<pre style="font-family:sans-serif;font-size:15px">${esc(text)}</pre>`));
  await Promise.all(jobs);
}
const sendMail = (env, to, subject, html) =>
  fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.MAIL_FROM || 'PureBite <onboarding@resend.dev>', to: [to], subject, html }),
  }).catch(() => {});
async function notifyOrder(env, o) {
  const lines = o.items.map((i) => `• ${i.n} × ${i.q} = ৳${i.q * i.p}`).join('\n');
  const text =
    `🛒 নতুন অর্ডার! ${o.ref}\n\nনাম: ${o.name}\nফোন: ${o.phone}\nঠিকানা: ${o.addr}, ${o.thana}, ${o.dist}\n\n${lines}\n\n` +
    `পণ্য: ৳${o.sub}${o.cd ? `\nছাড়: ৳${o.cd}` : ''}\nডেলিভারি (${o.zone}): ৳${o.ship}\nমোট: ৳${o.total}\nপেমেন্ট: ${o.pay}` +
    (o.aff ? `\nরেফারেল কোড: ${o.aff} (${o.affn || ''}) কমিশন ৳${o.cm || 0}` : '') + (o.note ? `\nনোট: ${o.note}` : '') + (o.vp ? '' : '\n⚠️ দাম যাচাই হয়নি (prices.json নেই)');
  const rows = o.items.map((i) => `<tr><td style="padding:6px;border-bottom:1px solid #eee">${esc(i.n)}</td><td style="padding:6px;border-bottom:1px solid #eee;text-align:center">${i.q}</td><td style="padding:6px;border-bottom:1px solid #eee;text-align:right">৳${i.q * i.p}</td></tr>`).join('');
  const html =
    `<div style="font-family:sans-serif;max-width:520px;margin:auto;border:2px solid #c9a24a;border-radius:12px;overflow:hidden"><div style="background:#0f3d2e;color:#e6c675;padding:16px;font-size:20px">🛒 নতুন অর্ডার — ${esc(o.ref)}</div><div style="padding:16px">` +
    `<p><b>${esc(o.name)}</b><br>📞 ${esc(o.phone)}<br>📍 ${esc(o.addr)}, ${esc(o.thana)}, ${esc(o.dist)}</p><table style="width:100%;border-collapse:collapse">${rows}</table>` +
    `<p>পণ্য: ৳${o.sub}${o.cd ? ` | ছাড়: ৳${o.cd}` : ''} | ডেলিভারি (${esc(o.zone)}): ৳${o.ship}</p><p style="font-size:20px"><b>মোট: ৳${o.total}</b></p><p>পেমেন্ট: ${esc(o.pay)}</p>` +
    `${o.aff ? `<p>রেফারেল কোড: ${esc(o.aff)}</p>` : ''}${o.note ? `<p>নোট: ${esc(o.note)}</p>` : ''}</div></div>`;
  await notifyOwner(env, text, `নতুন অর্ডার ${o.ref} — ৳${o.total} (${o.name})`, html);
}

// ---------- অর্ডারের অবস্থা বদল (সব জায়গায় একসাথে) ----------
async function setOrderSt(env, oid, st) {
  const o = await env.KV.get(oid, 'json');
  if (!o) return false;
  o.st = st;
  await env.KV.put(oid, JSON.stringify(o));
  let cu = null;
  if (o.uid) {
    cu = await getU(env, o.uid);
    const s = cu && (cu.orders || []).find((x) => x.id === oid);
    if (s) { s.st = st; await putU(env, cu); }
  }
  if (o.aff) {
    const id = await env.KV.get('AF:' + o.aff);
    const au = id && (!cu || cu.id !== id) ? await getU(env, id) : null;
    const s = au && au.comm && (au.comm.orders || []).find((x) => x.id === oid);
    if (s) { s.st = st; await putU(env, au); }
  }
  return true;
}

// ---------- কাস্টমার API ----------
async function userApi(p, request, env, ctx, u0) {
  if (!(env.ADMIN_KEY || env.TOKEN_SECRET)) return J({ ok: false, m: 'সার্ভারের ADMIN_KEY সেট করা হয়নি' }, 503);
  const ip = request.headers.get('CF-Connecting-IP') || 'x';
  const t = await request.text();
  if (t.length > 20000) return J({ ok: false, m: 'অনুরোধ অনেক বড়' }, 413);
  let b = {};
  try { b = JSON.parse(t || '{}') || {}; } catch (e) { return J({ ok: false, m: 'ভুল অনুরোধ' }, 400); }
  if (b.hp) return J({ ok: false });

  if (p === '/register') {
    if (await hit('reg', ip, 5)) return J({ ok: false, m: 'একটু অপেক্ষা করে আবার চেষ্টা করুন' }, 429);
    const name = String(b.name || '').trim().slice(0, 60), ident = normIdent(b.ident), addr = String(b.addr || '').trim().slice(0, 200);
    if (name.length < 2) return J({ ok: false, m: 'সঠিক নাম লিখুন' });
    if (!identOk(ident)) return J({ ok: false, m: 'সঠিক ইমেইল বা মোবাইল নম্বর দিন' });
    if (addr.length < 5) return J({ ok: false, m: 'ঠিকানা লিখুন' });
    const pe = pwErr(b.password); if (pe) return J({ ok: false, m: pe });
    const ex = await findU(env, ident);
    if (ex) {
      return ex.claimed
        ? J({ ok: false, e: 'exists', m: 'এই ইমেইল/নম্বরে আগেই অ্যাকাউন্ট আছে। লগইন করুন।' })
        : J({ ok: false, e: 'unclaimed', m: 'আপনার আগের অর্ডারের অ্যাকাউন্ট আছে। চালু করা হচ্ছে…' });
    }
    const pw = await mkPw(b.password);
    const u = newUser({ name, addr, claimed: true, ...pw, ...(ident.includes('@') ? { email: ident } : { phone: ident }) });
    await putU(env, u); await setIdx(env, u);
    return J({ ok: true, token: await mkTok(env, u), me: meOf(u) });
  }

  if (p === '/login') {
    if (await hit('login', ip, 2)) return J({ ok: false, m: 'একটু অপেক্ষা করে আবার চেষ্টা করুন' }, 429);
    const ident = normIdent(b.ident), u = await findU(env, ident);
    const bad = J({ ok: false, m: 'ইমেইল/মোবাইল বা পাসওয়ার্ড ভুল' });
    if (!u) return bad;
    if (!u.claimed) return J({ ok: false, e: 'unclaimed', m: 'আপনার আগের অর্ডারের অ্যাকাউন্ট আছে। "Register account" দিয়ে পাসওয়ার্ড সেট করে চালু করুন।' });
    if (u.lock && u.lock > Date.now()) return J({ ok: false, m: 'অনেকবার ভুল হয়েছে। ১০ মিনিট পরে চেষ্টা করুন' }, 429);
    if (!(await chkPw(b.password, u.salt, u.hash))) {
      u.fails = (u.fails || 0) + 1;
      if (u.fails >= 5) { u.fails = 0; u.lock = Date.now() + 10 * 60 * 1000; }
      await putU(env, u);
      return bad;
    }
    if (u.fails || u.lock) { u.fails = 0; u.lock = 0; await putU(env, u); }
    return J({ ok: true, token: await mkTok(env, u), me: meOf(u) });
  }

  if (p === '/claim') {
    if (await hit('claim', ip, 3)) return J({ ok: false, m: 'একটু অপেক্ষা করে আবার চেষ্টা করুন' }, 429);
    const ident = normIdent(b.ident), u = await findU(env, ident);
    if (!u) return J({ ok: false, m: 'অ্যাকাউন্ট পাওয়া যায়নি' });
    if (u.claimed) return J({ ok: false, m: 'এই অ্যাকাউন্ট আগেই চালু আছে। লগইন করুন।' });
    const pe = pwErr(b.password); if (pe) return J({ ok: false, m: pe });
    const pw = await mkPw(b.password);
    const ck = String(b.ck || '');
    let okCk = false;
    if (ck) { const h = await sha(ck); okCk = (u.ckh || []).some((x) => eq(x, h)); }
    if (okCk) {
      Object.assign(u, pw, { claimed: true, ckh: [], pend: null, pv: (u.pv || 0) + 1 });
      await putU(env, u);
      return J({ ok: true, token: await mkTok(env, u), me: meOf(u) });
    }
    const code = String(100000 + (rnd(4).reduce((a, x) => a * 256 + x, 0) % 900000));
    u.pend = { code, ...pw, ts: Date.now() };
    await putU(env, u);
    await notifyOwner(env, `🔔 অ্যাকাউন্ট চালুর আবেদন\nনাম: ${u.name}\nমোবাইল: ${u.phone || '-'}\nইমেইল: ${u.email || '-'}\nযাচাই কোড: ${code}\n(কাস্টমার এই কোড WhatsApp-এ পাঠালে অ্যাডমিন পেজ থেকে অনুমোদন দিন)`, `অ্যাকাউন্ট চালুর আবেদন — ${u.name}`).catch(() => {});
    return J({ ok: true, pending: true, code, phone: u.phone || u.email || ident });
  }

  if (p === '/otp/send') {
    const ident = normIdent(b.ident);
    if (!identOk(ident)) return J({ ok: false, m: 'সঠিক ইমেইল বা মোবাইল নম্বর দিন' });
    const u = await findU(env, ident);
    if (!u) return J({ ok: false, e: 'none', m: 'এই ইমেইল/নম্বরে কোনো অ্যাকাউন্ট নেই। রেজিস্ট্রেশন করুন।' });
    const to = ident.includes('@') ? ident : u.email;
    if (!to || !env.RESEND_API_KEY) return J({ ok: false, e: 'noprov', m: 'OTP পাঠানোর সেবা এখন চালু নেই। পাসওয়ার্ড দিয়ে লগইন করুন।' });
    if (await hit('otp', ident, 60)) return J({ ok: false, m: '১ মিনিট পরে আবার চেষ্টা করুন' }, 429);
    const code = String(100000 + (rnd(4).reduce((a, x) => a * 256 + x, 0) % 900000));
    await env.KV.put('OTP:' + ident, JSON.stringify({ h: await sha(code + '|' + ident), n: 0 }), { expirationTtl: 300 });
    await sendMail(env, to, `PureBite যাচাই কোড: ${code}`, `<div style="font-family:sans-serif;font-size:16px">আপনার PureBite যাচাই কোড: <b style="font-size:26px;letter-spacing:3px">${code}</b><br>কোডটি ৫ মিনিট বৈধ। কাউকে জানাবেন না।</div>`);
    return J({ ok: true });
  }

  if (p === '/otp/verify') {
    const ident = normIdent(b.ident), code = String(b.code || '').replace(/\D/g, '');
    const rec = await env.KV.get('OTP:' + ident, 'json');
    if (!rec) return J({ ok: false, m: 'কোডের মেয়াদ শেষ। আবার পাঠান।' });
    if (rec.n >= 5) { await env.KV.delete('OTP:' + ident); return J({ ok: false, m: 'অনেকবার ভুল। নতুন কোড নিন।' }); }
    if (!eq(rec.h, await sha(code + '|' + ident))) {
      rec.n++; await env.KV.put('OTP:' + ident, JSON.stringify(rec), { expirationTtl: 300 });
      return J({ ok: false, m: 'কোড মেলেনি' });
    }
    const u = await findU(env, ident);
    if (!u) return J({ ok: false, m: 'অ্যাকাউন্ট পাওয়া যায়নি' });
    if (b.password) {
      const pe = pwErr(b.password); if (pe) return J({ ok: false, m: pe });
      Object.assign(u, await mkPw(b.password), { claimed: true, pv: (u.pv || 0) + 1, fails: 0, lock: 0, pend: null });
    } else if (!u.claimed) {
      u.claimed = true; u.pend = null; // ইমেইল OTP মিলেছে = মালিকানা যাচাই
    }
    await env.KV.delete('OTP:' + ident);
    await putU(env, u);
    return J({ ok: true, token: await mkTok(env, u), me: meOf(u) });
  }

  // এখান থেকে লগইন লাগবে
  const u = u0 || (await authUser(env, request));
  if (!u || !u.claimed) return J({ ok: false, e: 'auth', m: 'আবার লগইন করুন' }, 401);

  if (p === '/me') return J({ ok: true, me: meOf(u) });
  if (p === '/me/cart') {
    const items = (Array.isArray(b.items) ? b.items : []).slice(0, 40).map((i) => ({ n: String(i.n || '').slice(0, 120), s: String(i.s || '').slice(0, 30), q: Math.min(99, Math.max(0, +i.q | 0)), p: Math.min(200000, Math.max(0, +i.p | 0)) })).filter((i) => i.q > 0 && i.n);
    u.cart = { items, ts: Date.now() };
    await putU(env, u);
    return J({ ok: true });
  }
  if (p === '/me/read') {
    const s = String(b.s || '').replace(/[^\w-]/g, '').slice(0, 80);
    if (!s) return J({ ok: false });
    u.reads = [{ s, h: String(b.h || '').slice(0, 160), c: String(b.c || '').slice(0, 40), ts: Date.now() }].concat((u.reads || []).filter((x) => x.s !== s)).slice(0, 60);
    await putU(env, u);
    return J({ ok: true });
  }
  if (p === '/me/update') {
    const name = String(b.name || '').trim().slice(0, 60), addr = String(b.addr || '').trim().slice(0, 200);
    if (name.length < 2) return J({ ok: false, m: 'সঠিক নাম লিখুন' });
    if (addr.length < 5) return J({ ok: false, m: 'ঠিকানা লিখুন' });
    u.name = name; u.addr = addr;
    await putU(env, u);
    return J({ ok: true, me: meOf(u) });
  }
  if (p === '/me/password') {
    if (u.hash && !(await chkPw(b.old, u.salt, u.hash))) return J({ ok: false, m: 'বর্তমান পাসওয়ার্ড ভুল' });
    const pe = pwErr(b.new); if (pe) return J({ ok: false, m: pe });
    Object.assign(u, await mkPw(b.new), { pv: (u.pv || 0) + 1 });
    await putU(env, u);
    return J({ ok: true, token: await mkTok(env, u) });
  }
  if (p === '/me/comm/request') {
    u.comm = u.comm || { st: 'none', orders: [] };
    if (u.comm.st === 'approved') return J({ ok: true, st: 'approved' });
    if (u.comm.st === 'pending' && u.comm.reqTs && Date.now() - u.comm.reqTs < 60000) return J({ ok: true, st: 'pending' });
    u.comm.st = 'pending'; u.comm.reqTs = Date.now(); u.comm.note = String(b.note || '').slice(0, 200);
    await putU(env, u);
    ctx.waitUntil(notifyOwner(env, `💼 কমিশন সদস্য আবেদন\nনাম: ${u.name}\nমোবাইল: ${u.phone || '-'}\nইমেইল: ${u.email || '-'}\n(কাস্টমার কল/WhatsApp করলে অ্যাডমিন পেজ → কাস্টমার থেকে অনুমোদন দিন)`, `কমিশন আবেদন — ${u.name}`).catch(() => {}));
    return J({ ok: true, st: 'pending' });
  }
  if (p === '/me/comm') {
    const c = u.comm || { st: 'none' };
    if (c.st !== 'approved') return J({ ok: true, comm: { st: c.st || 'none' } });
    const cfg = await getCfg(env);
    return J({ ok: true, comm: { st: 'approved', code: c.code, ...commStats(c), orders: (c.orders || []).slice(0, 100), pays: (c.pays || []).slice(0, 50).map((x) => ({ id: x.id, ts: x.ts, amt: x.amt, m: x.m, trx: x.trx, note: x.note, img: !!x.img })), dr: c.rate == null ? cfg.rate : c.rate, pp: cfg.pp || {}, hide: cfg.hide || [], ws: { pct: +cfg.wsPct || 0, note: cfg.wsNote || '' } } });
  }
  if (p === '/me/comm/proof') {
    const c = u.comm || {};
    const pay = (c.pays || []).find((x) => x.id === String(b.pid || ''));
    if (!pay || !pay.img) return J({ ok: false, m: 'প্রমাণ নেই' });
    return J({ ok: true, img: (await env.KV.get('IMG:' + u.id + ':' + pay.id)) || '' });
  }
  return J({ ok: false, m: 'not found' }, 404);
}

// ---------- অ্যাডমিন API ----------
async function adminApi(request, env, ctx) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (!env.ADMIN_KEY) return J({ ok: false, m: 'ADMIN_KEY সেট করা নেই' }, 503, true);
  const ip = request.headers.get('CF-Connecting-IP') || 'x';
  const fk = new Request('https://fail.local/' + encodeURIComponent(ip));
  const fl = await caches.default.match(fk);
  if (fl && +(await fl.clone().text()) >= 5) return J({ ok: false, m: 'অনেকবার ভুল। ১৫ মিনিট পরে চেষ্টা করুন' }, 429, true);
  const t = await request.text();
  if (t.length > 700000) return J({ ok: false, m: 'অনুরোধ অনেক বড়' }, 413, true);
  let b = {};
  try { b = JSON.parse(t || '{}') || {}; } catch (e) { return J({ ok: false, m: 'ভুল অনুরোধ' }, 400, true); }
  if (!eq(await sha(b.key || ''), await sha(env.ADMIN_KEY))) {
    const n = (fl ? +(await fl.clone().text()) || 0 : 0) + 1;
    await caches.default.put(fk, new Response(String(n), { headers: { 'Cache-Control': 'max-age=900' } }));
    return J({ ok: false, m: 'ভুল অ্যাডমিন কী' }, 401, true);
  }
  const R = (o, s) => J(o, s || 200, true);
  const a = b.a;

  if (a === 'orders') {
    const before = String(b.before || '');
    let keys = [], cursor;
    do {
      const r = await env.KV.list({ prefix: 'PB', cursor });
      keys = keys.concat(r.keys.map((k) => k.name));
      cursor = r.list_complete ? undefined : r.cursor;
    } while (cursor);
    keys.sort();
    if (before) keys = keys.filter((k) => k < before);
    const page = keys.slice(-40).reverse();
    const vals = (await Promise.all(page.map((k) => env.KV.get(k, 'json')))).filter(Boolean).map((o) => ({ ...o, st: normSt(o.st) }));
    return R({ ok: true, orders: vals, more: keys.length > 40 ? page[page.length - 1] : '', pmis: (await env.KV.get('PMIS', 'json')) || null, pj: !!(await loadPrices(env, new URL(request.url))) });
  }
  if (a === 'list') {
    let L = [], cursor;
    for (let i = 0; i < 5; i++) {
      const r = await env.KV.list({ prefix: 'U:', cursor });
      L = L.concat(r.keys.map((k) => ({ id: k.name.slice(2), ...(k.metadata || {}) })));
      if (r.list_complete) break;
      cursor = r.cursor;
    }
    L.sort((x, y) => (y.t || 0) - (x.t || 0));
    return R({ ok: true, list: L.map((x) => ({ id: x.id, n: x.n || '', p: x.p || '', e: x.e || '', o: x.o || 0, k: x.k || 0, q: x.q || 0, c: x.c || 0, cm: x.cm || 'none', t: x.t || 0 })) });
  }
  if (a === 'cfg') return R({ ok: true, cfg: await getCfg(env) });
  if (a === 'cfgset') {
    const c = await getCfg(env);
    if (b.rate !== undefined) c.rate = Math.min(100, Math.max(0, +b.rate || 0));
    if (b.wsPct !== undefined) c.wsPct = Math.min(90, Math.max(0, +b.wsPct || 0));
    if (b.wsNote !== undefined) c.wsNote = String(b.wsNote).slice(0, 400);
    if (b.pp && typeof b.pp === 'object') {
      c.pp = {};
      for (const k of Object.keys(b.pp).slice(0, 400)) { const v = b.pp[k]; if (v !== '' && v != null && isFinite(+v)) c.pp[String(k).slice(0, 120)] = Math.min(100, Math.max(0, +v)); }
    }
    if (Array.isArray(b.hide)) c.hide = b.hide.slice(0, 400).map((x) => String(x).slice(0, 120));
    await env.KV.put('CFG', JSON.stringify(c));
    return R({ ok: true, cfg: c });
  }
  if (a === 'ost') {
    const st = normSt(b.st);
    if (!ST.includes(st)) return R({ ok: false, m: 'ভুল অবস্থা' }, 400);
    const oid = String(b.oid || b.ref || '');
    if (!/^PB[0-9A-Z]+$/.test(oid)) return R({ ok: false, m: 'ভুল রেফ' }, 400);
    return R((await setOrderSt(env, oid, st)) ? { ok: true } : { ok: false, m: 'অর্ডার নেই' }, 200);
  }
  if (a === 'odel') {
    const oid = String(b.ref || '');
    if (!/^PB[0-9A-Z]+$/.test(oid)) return R({ ok: false, m: 'ভুল রেফ' }, 400);
    await setOrderSt(env, oid, 'cancelled').catch(() => {});
    await env.KV.delete(oid);
    return R({ ok: true });
  }

  const id = String(b.id || '').replace(/[^a-z0-9]/g, '');
  const u = id ? await getU(env, id) : null;
  if (!u) return R({ ok: false, m: 'অ্যাকাউন্ট পাওয়া যায়নি' }, 404);
  u.comm = u.comm || { st: 'none', orders: [] };

  if (a === 'get') {
    const c = u.comm;
    return R({ ok: true, u: { id: u.id, name: u.name, phone: u.phone, email: u.email, addr: u.addr, claimed: !!u.claimed, created: u.created, pend: u.pend ? { code: u.pend.code } : null, cart: u.cart || { items: [] }, orders: (u.orders || []).map((o) => ({ id: o.id, ts: o.ts, st: o.st, total: o.total, pay: o.pay, dist: o.dist || '', items: o.items || [] })), reads: (u.reads || []).length, comm: { st: c.st || 'none', code: c.code || '', rate: c.rate == null ? '' : c.rate, note: c.note || '', orders: (c.orders || []).slice(0, 100), pays: (c.pays || []).map((x) => ({ id: x.id, ts: x.ts, amt: x.amt, m: x.m, trx: x.trx, note: x.note, img: !!x.img })), ...commStats(c) } } });
  }
  if (a === 'save') {
    const name = String(b.name || '').trim().slice(0, 60), addr = String(b.addr || '').trim().slice(0, 200);
    const ph = normIdent(b.phone || ''), em = normIdent(b.email || '');
    if (name.length < 2) return R({ ok: false, m: 'নাম লিখুন' });
    if (ph && !BD.test(ph)) return R({ ok: false, m: 'মোবাইল নম্বর ঠিক নয়' });
    if (em && !EM.test(em)) return R({ ok: false, m: 'ইমেইল ঠিক নয়' });
    for (const k of [ph, em]) { if (k) { const o = await env.KV.get('X:' + k); if (o && o !== u.id) return R({ ok: false, m: k + ' অন্য অ্যাকাউন্টে আছে' }); } }
    for (const k of [u.phone, u.email]) if (k && k !== ph && k !== em) await env.KV.delete('X:' + k);
    Object.assign(u, { name, addr, phone: ph, email: em });
    await putU(env, u); await setIdx(env, u);
    return R({ ok: true });
  }
  if (a === 'setpw') {
    const pe = pwErr(b.password); if (pe) return R({ ok: false, m: pe });
    Object.assign(u, await mkPw(b.password), { claimed: true, pend: null, pv: (u.pv || 0) + 1, fails: 0, lock: 0 });
    await putU(env, u);
    return R({ ok: true });
  }
  if (a === 'approve') {
    if (!u.pend) return R({ ok: false, m: 'কোনো আবেদন নেই' });
    Object.assign(u, { salt: u.pend.salt, hash: u.pend.hash, claimed: true, pend: null, ckh: [], pv: (u.pv || 0) + 1 });
    await putU(env, u);
    return R({ ok: true });
  }
  if (a === 'reject') { u.pend = null; await putU(env, u); return R({ ok: true }); }
  if (a === 'del') {
    for (const k of [u.phone, u.email]) if (k) await env.KV.delete('X:' + k);
    if (u.comm.code) { const o = await env.KV.get('AF:' + u.comm.code); if (o === u.id) await env.KV.delete('AF:' + u.comm.code); }
    await env.KV.delete('U:' + u.id);
    return R({ ok: true });
  }
  if (a === 'cset') {
    const c = u.comm, st = ['approved', 'rejected', 'pending', 'none'].includes(b.st) ? b.st : c.st;
    const cfg = await getCfg(env);
    if (b.rate !== undefined && b.rate !== '') c.rate = Math.min(100, Math.max(0, +b.rate || 0));
    if (c.rate == null) c.rate = cfg.rate;
    if (st === 'approved') {
      let code = String(b.code || c.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
      if (code.length < 3) code = 'PB' + rndStr(4);
      const own = await env.KV.get('AF:' + code);
      if (own && own !== u.id) return R({ ok: false, m: 'এই কোড অন্য সদস্যের। আলাদা কোড দিন' });
      if (c.code && c.code !== code) { const o = await env.KV.get('AF:' + c.code); if (o === u.id) await env.KV.delete('AF:' + c.code); }
      c.code = code;
      await env.KV.put('AF:' + code, u.id);
    } else if (c.code) {
      const o = await env.KV.get('AF:' + c.code);
      if (o === u.id) await env.KV.delete('AF:' + c.code);
    }
    c.st = st;
    await putU(env, u);
    return R({ ok: true, code: c.code || '' });
  }
  if (a === 'cpay') {
    const amt = Math.round(+b.amount || 0);
    if (!(amt > 0)) return R({ ok: false, m: 'টাকার পরিমাণ দিন' });
    const pid = 'P' + Date.now().toString(36) + rndStr(3);
    const img = String(b.img || '');
    if (img && (!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(img) || img.length > 600000)) return R({ ok: false, m: 'ছবি ঠিক নয় বা বড়' });
    u.comm.pays = [{ id: pid, ts: Date.now(), amt, m: String(b.method || '').slice(0, 20), trx: String(b.trx || '').slice(0, 40), note: String(b.note || '').slice(0, 120), img: !!img }].concat(u.comm.pays || []).slice(0, 200);
    if (img) await env.KV.put('IMG:' + u.id + ':' + pid, img);
    await putU(env, u);
    return R({ ok: true });
  }
  if (a === 'cpaydel') {
    const pid = String(b.pid || '');
    u.comm.pays = (u.comm.pays || []).filter((x) => x.id !== pid);
    await env.KV.delete('IMG:' + u.id + ':' + pid);
    await putU(env, u);
    return R({ ok: true });
  }
  if (a === 'proof') {
    return R({ ok: true, img: (await env.KV.get('IMG:' + u.id + ':' + String(b.pid || ''))) || '' });
  }
  if (a === 'crj') {
    const o = (u.comm.orders || []).find((x) => x.id === String(b.oid || ''));
    if (!o) return R({ ok: false, m: 'অর্ডার নেই' });
    o.rj = o.rj ? 0 : 1;
    await putU(env, u);
    return R({ ok: true, rj: o.rj });
  }
  return R({ ok: false, m: 'not found' }, 404);
}

// ---------- বট/স্প্যাম ও ভ্যালিডেশন ----------
function junk(t, min) {
  t = String(t || '').trim();
  if (t.length < min) return true;
  if (!/\p{L}/u.test(t)) return true;                 // একটাও অক্ষর নেই (শুধু সংখ্যা/চিহ্ন)
  if (/^(.)\1{3,}$/u.test(t.replace(/\s/g, ''))) return true; // aaaa, ....
  if (/^(test|asdf|qwer|xxxx|abc|na|n\/a|none)\b/i.test(t) && t.length < 8) return true;
  return false;
}
async function verifyTurnstile(env, token, ip) {
  if (!token || token.length > 2100) return 'no-token';
  try {
    const f = new FormData();
    f.append('secret', String(env.TURNSTILE_SECRET).trim()); f.append('response', token); if (ip) f.append('remoteip', ip);
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: f });
    const d = await r.json();
    return d && d.success ? '' : ((d && d['error-codes'] && d['error-codes'].join(',')) || 'failed');
  } catch (e) { return 'net-error'; }
}
async function phoneLimited(env, phone) {
  const k = 'RL:' + phone;
  const n = +((await env.KV.get(k)) || 0);
  if (n >= 6) return true;
  await env.KV.put(k, String(n + 1), { expirationTtl: 3600 });
  return false;
}
// ক্যাটালগ ও prices.json না মিললে অ্যাডমিনকে জানানো (১০ মিনিটে একবার লেখা হয়)
function pmis(env, ctx, kind, what) {
  ctx.waitUntil((async () => {
    if (await hit('pmis', 'g', 600)) return;
    const o = (await env.KV.get('PMIS', 'json')) || { n: 0 };
    await env.KV.put('PMIS', JSON.stringify({ ts: Date.now(), n: (o.n || 0) + 1, kind, what: String(what).slice(0, 120) }), { expirationTtl: 3 * 86400 });
  })().catch(() => {}));
  return null;
}

// ---------- সার্ভারের দাম যাচাই (prices.json) ----------
let PRC = { t: 0, v: null };
async function loadPrices(env, u) {
  if (Date.now() - PRC.t < 60000) return PRC.v;
  let v = null;
  try {
    const r = await env.ASSETS.fetch(new Request(u.origin + '/prices.json', { headers: { Accept: 'application/json' } }));
    if (r.ok && /json|text/.test(r.headers.get('content-type') || '')) {
      const d = await r.json();
      if (d && d.items && typeof d.items === 'object') v = { items: d.items, combos: Array.isArray(d.combos) ? d.combos : [] };
    }
  } catch (e) { v = null; }
  PRC = { t: Date.now(), v };
  return v;
}

// ---------- ওয়েবসাইট থেকে অর্ডার ----------
async function orderApi(request, env, ctx, u) {
  if (request.method !== 'POST') return J({ ok: false, m: 'method' }, 405);
  const og = request.headers.get('Origin');
  if (og && !okOrigin(og, u)) return J({ ok: false, m: 'অনুমতি নেই' }, 403);
  const rk = new Request('https://rl.local/' + encodeURIComponent(request.headers.get('CF-Connecting-IP') || 'x'));
  if (await caches.default.match(rk)) return J({ ok: false, m: 'একটু অপেক্ষা করে আবার চেষ্টা করুন' }, 429);
  try {
    const t = await request.text();
    if (t.length > 20000) return J({ ok: false, m: 'অনুরোধ অনেক বড়' }, 413);
    const b = JSON.parse(t);
    if (b.hp) return J({ ok: false });
    const phone = String(b.phone || '').replace(/\D/g, '').slice(-11);
    const items = (Array.isArray(b.items) ? b.items : []).slice(0, 40).map((i) => ({ n: String(i.n).slice(0, 120), s: String(i.s || '').slice(0, 30), q: +i.q | 0, p: +i.p | 0 }));
    const name = String(b.name || '').trim().slice(0, 60);
    if (!/^01[3-9]\d{8}$/.test(phone) || name.length < 2 || !items.length || items.some((i) => i.q < 1 || i.q > 99 || i.p < 0 || i.p > 200000)) return J({ ok: false, m: 'নাম, সঠিক মোবাইল নম্বর ও পণ্যের তথ্য দিন' });
    const addr0 = String(b.addr || '').trim();
    if (junk(name, 2) || junk(addr0, 8)) return J({ ok: false, m: 'সঠিক নাম ও পূর্ণ ঠিকানা লিখুন' });
    if (env.TURNSTILE_SECRET) {
      const ec = await verifyTurnstile(env, String(b.tt || ''), request.headers.get('CF-Connecting-IP') || '');
      if (ec) return J({ ok: false, m: '"আমি রোবট নই" যাচাই সম্পন্ন হয়নি (কোড: ' + ec + ')। পেজ রিফ্রেশ করে আবার চেষ্টা করুন' }, 403);
    }
    if (await phoneLimited(env, phone)) return J({ ok: false, m: 'এই নম্বর থেকে অল্প সময়ে অনেক অর্ডার এসেছে। কিছুক্ষণ পরে চেষ্টা করুন বা আমাদের কল করুন' }, 429);
    const z = Z[b.dz];
    if (!z) return J({ ok: false, m: 'ডেলিভারি এলাকা বাছুন' });
    // দাম ও ছাড় সার্ভার নিজে যাচাই করে — ব্রাউজারের অঙ্ক বিশ্বাস করে না
    const pr = await loadPrices(env, u);
    let vp = 0, cdMax = Infinity;
    if (pr) {
      for (const i of items) {
        const sp = pr.items[i.n];
        if (sp == null) return pmis(env, ctx, 'unknown', i.n) || J({ ok: false, m: '“' + i.n.slice(0, 40) + '” পণ্যটি এখন পাওয়া যাচ্ছে না। পেজ রিফ্রেশ করে আবার চেষ্টা করুন' });
        if (i.p !== Math.round(+sp)) return pmis(env, ctx, 'price', i.n + ' (ক্যাটালগে ' + i.p + ', সার্ভারে ' + Math.round(+sp) + ')') || J({ ok: false, m: 'পণ্যের দাম বদলেছে। পেজ রিফ্রেশ (নতুন করে লোড) করে আবার অর্ডার করুন' });
      }
      const qty = {};
      items.forEach((i) => { qty[i.n] = (qty[i.n] || 0) + i.q; });
      cdMax = 0;
      for (const c of pr.combos) {
        if (!Array.isArray(c.items) || !c.items.length) continue;
        const t = Math.min(...c.items.map((x) => Math.floor((qty[x.n] || 0) / (+x.q || 1))));
        if (t >= 1) cdMax += (+c.save || 0) * t;
      }
      vp = 1;
    }
    const sub = items.reduce((a, i) => a + i.q * i.p, 0), cd = Math.min(sub, cdMax, Math.max(0, +b.cd | 0)), total = sub - cd + z[1];
    const ref = 'PB' + Date.now().toString(36).toUpperCase();
    await caches.default.put(rk, new Response('1', { headers: { 'Cache-Control': 'max-age=15' } }));
    const addr = String(b.addr || '').slice(0, 200);
    const mail = normIdent(b.email || '');
    const em = EM.test(mail) ? mail : '';

    // কাস্টমার অ্যাকাউন্টের সাথে যুক্ত করা
    let cu = null, ck = '';
    if (env.ADMIN_KEY || env.TOKEN_SECRET) {
      cu = await authUser(env, request).catch(() => null);
      if (!cu) cu = (await findU(env, phone)) || (em ? await findU(env, em) : null);
      if (!cu) cu = newUser({ name, phone, email: em, addr });
      if (!cu.claimed) { ck = rndStr(18); cu.ckh = [await sha(ck)].concat(cu.ckh || []).slice(0, 3); }
      if (!cu.addr) cu.addr = addr;
      if (!cu.phone && !(await findU(env, phone))) cu.phone = phone;
      if (!cu.email && em && !(await findU(env, em))) cu.email = em;
    }
    // রেফারেল (কমিশন সদস্য)
    const code = String(b.ref || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
    let au = null;
    if (code && cu) { au = await affU(env, code); if (au && (au.id === cu.id || au.phone === phone)) au = null; }

    const order = { ref, ts: new Date().toISOString(), name, phone, addr, dist: String(b.dist || '').slice(0, 40), thana: String(b.thana || '').slice(0, 40), pay: String(b.pay || '').slice(0, 60), note: String(b.note || '').slice(0, 300), items, sub, cd, ship: z[1], total, zone: z[0], vp, st: 'new', uid: cu ? cu.id : '', aff: au ? code : '', rc: code };
    await env.KV.put(ref, JSON.stringify(order));
    if (cu) {
      cu.orders = [{ id: ref, ts: Date.now(), st: 'new', total, ship: z[1], pay: order.pay, zone: z[0], dist: order.dist, items: items.map((i) => ({ n: i.n, s: i.s, q: i.q, p: i.p })) }].concat(cu.orders || []).slice(0, 100);
      await putU(env, cu); await setIdx(env, cu);
    }
    if (au) {
      const cfg = await getCfg(env);
      const cm = calcComm(cfg, items, sub, cd, au.comm.rate == null ? cfg.rate : au.comm.rate);
      au.comm.orders = [{ id: ref, ts: Date.now(), st: 'new', b: Math.max(0, sub - cd), c: cm, n: name.slice(0, 30) }].concat(au.comm.orders || []).slice(0, 300);
      await putU(env, au);
      order.cm = cm; order.affn = au.name;
      await env.KV.put(ref, JSON.stringify(order));
    }
    ctx.waitUntil(notifyOrder(env, order).catch(() => {}));
    return J({ ok: true, ref, sub, cd, ship: z[1], total, zone: z[0], ...(ck ? { ck } : {}) });
  } catch (e) {
    return J({ ok: false, m: 'সার্ভারে সমস্যা হয়েছে। আবার চেষ্টা করুন' }, 500);
  }
}

const ALLOW = ['https://purebite16.github.io'];
const okOrigin = (og, u) => og === u.origin || ALLOW.includes(og);
const USER_PATHS = new Set(['/register', '/login', '/claim', '/otp/send', '/otp/verify', '/me', '/me/cart', '/me/read', '/me/update', '/me/password', '/me/comm', '/me/comm/request', '/me/comm/proof']);

async function refHit(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'x';
  let b = {};
  try { b = JSON.parse((await request.text()).slice(0, 500) || '{}'); } catch (e) { return J({ ok: false }); }
  const code = String(b.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
  if (code.length < 3 || (await hit('rf-' + code, ip, 3600)) || (await hit('rfip', ip, 5))) return J({ ok: true });
  const au = await affU(env, code);
  if (!au) return J({ ok: true });
  const d = today();
  au.comm.ck = au.comm.ck && au.comm.ck.d === d ? au.comm.ck : { d, n: 0, t: (au.comm.ck && au.comm.ck.t) || 0 };
  au.comm.ck.n++; au.comm.ck.t++;
  await putU(env, au);
  return J({ ok: true });
}

const handle = async (request, env, ctx) => {
    const u = new URL(request.url);
    const p = u.pathname.replace(/\/+$/, '') || '/';
    if (p === '/admin' && (request.method === 'POST' || request.method === 'OPTIONS')) return adminApi(request, env, ctx);
    if (p === '/api/orders') return orderApi(request, env, ctx, u);
    if (p === '/api/ref' && request.method === 'POST') return refHit(request, env);
    if (USER_PATHS.has(p) && request.method === 'POST') {
      const og = request.headers.get('Origin');
      if (og && !okOrigin(og, u)) return J({ ok: false, m: 'অনুমতি নেই' }, 403);
      try { return await userApi(p, request, env, ctx); } catch (e) { return J({ ok: false, m: 'সার্ভারে সমস্যা হয়েছে। আবার চেষ্টা করুন' }, 500); }
    }
    return env.ASSETS.fetch(request);
};

export default {
  async fetch(request, env, ctx) {
    const u = new URL(request.url);
    const p = u.pathname.replace(/\/+$/, '') || '/';
    const og = request.headers.get('Origin');
    const api = p === '/api/orders' || p === '/api/ref' || USER_PATHS.has(p);
    const cors = api && og && okOrigin(og, u) ? { 'Access-Control-Allow-Origin': og, 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Max-Age': '600', Vary: 'Origin' } : null;
    if (api && request.method === 'OPTIONS') return new Response(null, { status: cors ? 204 : 403, headers: cors || {} });
    const r = await handle(request, env, ctx);
    const h = new Headers(r.headers);
    h.set('X-Content-Type-Options', 'nosniff');
    h.set('X-Frame-Options', 'DENY');
    h.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    if (p === '/admin.html' || p === '/admin') h.set('X-Robots-Tag', 'noindex, nofollow');
    if (cors) for (const k in cors) h.set(k, cors[k]);
    return new Response(r.body, { status: r.status, headers: h });
  },
};
