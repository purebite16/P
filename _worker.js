const H = { 'Cache-Control': 'no-store' };
const J = (o, s = 200) => Response.json(o, { status: s, headers: H });
const Z = [['ঢাকা সিটির ভেতরে', 60], ['ঢাকা সিটির বাইরে', 90], ['ঢাকা জেলার বাইরে', 110]];
const ST = ['নতুন', 'প্যাকিং', 'পাঠানো হয়েছে', 'ডেলিভারি হয়েছে', 'বাতিল'];
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// ---------- নোটিফিকেশন (WhatsApp + ইমেইল একসাথে) ----------
async function notify(env, o) {
  const lines = o.items.map((i) => `• ${i.n} × ${i.q} = ৳${i.q * i.p}`).join('\n');
  const text =
    `🛒 নতুন অর্ডার! ${o.ref}\n\n` +
    `নাম: ${o.name}\nফোন: ${o.phone}\nঠিকানা: ${o.addr}, ${o.thana}, ${o.dist}\n\n` +
    `${lines}\n\n` +
    `পণ্য: ৳${o.sub}${o.cd ? `\nছাড়: ৳${o.cd}` : ''}\nডেলিভারি (${o.zone}): ৳${o.ship}\n` +
    `মোট: ৳${o.total}\nপেমেন্ট: ${o.pay}` + (o.note ? `\nনোট: ${o.note}` : '');
  const jobs = [];
  // WhatsApp (CallMeBot)
  if (env.CALLMEBOT_KEY) {
    const ph = env.WA_PHONE || '+8801344628989';
    jobs.push(
      fetch(`https://api.callmebot.com/whatsapp.php?phone=${encodeURIComponent(ph)}&text=${encodeURIComponent(text)}&apikey=${encodeURIComponent(env.CALLMEBOT_KEY)}`).catch(() => {})
    );
  }
  // ইমেইল (Resend)
  if (env.RESEND_API_KEY) {
    const to = env.NOTIFY_EMAIL || 'purebite16@gmail.com';
    const rows = o.items.map((i) => `<tr><td style="padding:6px;border-bottom:1px solid #eee">${esc(i.n)}</td><td style="padding:6px;border-bottom:1px solid #eee;text-align:center">${i.q}</td><td style="padding:6px;border-bottom:1px solid #eee;text-align:right">৳${i.q * i.p}</td></tr>`).join('');
    const html =
      `<div style="font-family:sans-serif;max-width:520px;margin:auto;border:2px solid #c9a24a;border-radius:12px;overflow:hidden">` +
      `<div style="background:#0f3d2e;color:#e6c675;padding:16px;font-size:20px">🛒 নতুন অর্ডার — ${esc(o.ref)}</div><div style="padding:16px">` +
      `<p><b>${esc(o.name)}</b><br>📞 ${esc(o.phone)}<br>📍 ${esc(o.addr)}, ${esc(o.thana)}, ${esc(o.dist)}</p>` +
      `<table style="width:100%;border-collapse:collapse">${rows}</table>` +
      `<p>পণ্য: ৳${o.sub}${o.cd ? ` | ছাড়: ৳${o.cd}` : ''} | ডেলিভারি (${esc(o.zone)}): ৳${o.ship}</p>` +
      `<p style="font-size:20px"><b>মোট: ৳${o.total}</b></p><p>পেমেন্ট: ${esc(o.pay)}</p>${o.note ? `<p>নোট: ${esc(o.note)}</p>` : ''}</div></div>`;
    jobs.push(
      fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: env.MAIL_FROM || 'PureBite অর্ডার <onboarding@resend.dev>', to: [to], subject: `নতুন অর্ডার ${o.ref} — ৳${o.total} (${o.name})`, html }),
      }).catch(() => {})
    );
  }
  await Promise.all(jobs);
}

// ---------- অ্যাডমিন ----------
async function admin(request, env, u) {
  if (!env.ADMIN_KEY) return J({ ok: false, m: 'ADMIN_KEY সেট করা নেই' }, 503);
  const ip = request.headers.get('CF-Connecting-IP') || 'x';
  const fk = new Request('https://fail.local/' + encodeURIComponent(ip));
  if (await caches.default.match(fk)) return J({ ok: false, m: 'কিছুক্ষণ পরে চেষ্টা করুন' }, 429);
  const given = request.headers.get('x-admin-key') || '';
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([crypto.subtle.digest('SHA-256', enc.encode(given)), crypto.subtle.digest('SHA-256', enc.encode(env.ADMIN_KEY))]);
  const x = new Uint8Array(a), y = new Uint8Array(b);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  if (d !== 0) {
    await caches.default.put(fk, new Response('1', { headers: { 'Cache-Control': 'max-age=3' } }));
    return J({ ok: false, m: 'ভুল অ্যাডমিন কী' }, 401);
  }
  const path = u.pathname.replace(/\/+$/, '');
  if (path === '/api/admin/orders') {
    const before = u.searchParams.get('before') || '';
    let keys = [], cursor;
    do {
      const r = await env.KV.list({ prefix: 'PB', cursor });
      keys = keys.concat(r.keys.map((k) => k.name));
      cursor = r.list_complete ? undefined : r.cursor;
    } while (cursor);
    keys.sort();
    if (before) keys = keys.filter((k) => k < before);
    const page = keys.slice(-40).reverse();
    const vals = await Promise.all(page.map((k) => env.KV.get(k, 'json')));
    return J({ ok: true, orders: vals.filter(Boolean), more: keys.length > 40 ? page[page.length - 1] : '' });
  }
  if (request.method !== 'POST') return J({ ok: false, m: 'method' }, 405);
  const b2 = await request.json().catch(() => ({}));
  const ref = String(b2.ref || '');
  if (!/^PB[0-9A-Z]+$/.test(ref)) return J({ ok: false, m: 'ভুল রেফ' }, 400);
  if (path === '/api/admin/status') {
    if (!ST.includes(b2.st)) return J({ ok: false, m: 'ভুল স্ট্যাটাস' }, 400);
    const o = await env.KV.get(ref, 'json');
    if (!o) return J({ ok: false, m: 'অর্ডার নেই' }, 404);
    o.st = b2.st;
    await env.KV.put(ref, JSON.stringify(o));
    return J({ ok: true });
  }
  if (path === '/api/admin/delete') {
    await env.KV.delete(ref);
    return J({ ok: true });
  }
  return J({ ok: false, m: 'not found' }, 404);
}

export default {
  async fetch(request, env, ctx) {
    const u = new URL(request.url);
    const p = u.pathname.replace(/\/+$/, '');
    if (p.startsWith('/api/admin/')) {
      const og0 = request.headers.get('Origin');
      if (og0 && og0 !== u.origin) return J({ ok: false, m: 'অনুমতি নেই' }, 403);
      return admin(request, env, u);
    }
    if (p !== '/api/orders') return env.ASSETS.fetch(request);
    if (request.method !== 'POST') return J({ ok: false, m: 'method' }, 405);
    const og = request.headers.get('Origin');
    if (og && og !== u.origin) return J({ ok: false, m: 'অনুমতি নেই' }, 403);
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
      const z = Z[b.dz] || ['', 0];
      const sub = items.reduce((a, i) => a + i.q * i.p, 0), cd = Math.min(sub, Math.max(0, +b.cd | 0)), total = sub - cd + z[1];
      const ref = 'PB' + Date.now().toString(36).toUpperCase();
      await caches.default.put(rk, new Response('1', { headers: { 'Cache-Control': 'max-age=15' } }));
      const order = { ref, ts: new Date().toISOString(), name, phone, addr: String(b.addr || '').slice(0, 200), dist: String(b.dist || '').slice(0, 40), thana: String(b.thana || '').slice(0, 40), pay: String(b.pay || '').slice(0, 60), note: String(b.note || '').slice(0, 300), items, sub, cd, ship: z[1], total, zone: z[0], st: 'নতুন' };
      await env.KV.put(ref, JSON.stringify(order));
      ctx.waitUntil(notify(env, order).catch(() => {}));
      return J({ ok: true, ref, sub, cd, ship: z[1], total, zone: z[0] });
    } catch (e) {
      return J({ ok: false, m: 'সার্ভারে সমস্যা হয়েছে। আবার চেষ্টা করুন' }, 500);
    }
  },
};
