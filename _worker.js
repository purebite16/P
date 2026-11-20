const H = { 'Cache-Control': 'no-store' };
const J = (o, s = 200) => Response.json(o, { status: s, headers: H });
const Z = [['ঢাকা সিটির ভেতরে', 60], ['ঢাকা সিটির বাইরে', 90], ['ঢাকা জেলার বাইরে', 110]];
export default {
  async fetch(request, env) {
    const u = new URL(request.url);
    if (u.pathname.replace(/\/+$/, '') !== '/api/orders') return env.ASSETS.fetch(request);
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
      await env.KV.put(ref, JSON.stringify({ ref, ts: new Date().toISOString(), name, phone, addr: String(b.addr || '').slice(0, 200), dist: String(b.dist || '').slice(0, 40), thana: String(b.thana || '').slice(0, 40), pay: String(b.pay || '').slice(0, 60), note: String(b.note || '').slice(0, 300), items, sub, cd, ship: z[1], total, zone: z[0] }));
      return J({ ok: true, ref, sub, cd, ship: z[1], total, zone: z[0] });
    } catch (e) {
      return J({ ok: false, m: 'সার্ভারে সমস্যা হয়েছে। আবার চেষ্টা করুন' }, 500);
    }
  },
};
