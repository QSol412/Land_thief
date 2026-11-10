// Territory Canvas backend: Cloudflare Pages Function served at /api/canvas/*
// (more specific than functions/api/[[path]].js, so it takes priority for /api/canvas/*)
//
// Needs only the R2 binding you already have:  SYNC_BUCKET
// Accounts are username + password (no Google sign-in). Passwords are hashed with
// PBKDF2 + a random salt; sessions are random tokens stored in R2.
//
// Optional variable: TURN_MS (default 300000 = 5 minutes)
//
// Routes
//   GET  state?since=V        -> world {v,cells,o,t,w,h,now} or {same:1}
//   GET  me                   -> your account info
//   POST register {username,password,territory?,color}
//   POST login    {username,password}
//   POST logout
//   POST turn     {action:'claim'|'wall'|'attack', cells:[[x,y],...]}
//   POST team/create {name,color}   POST team/join {id}   POST team/leave

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const TE = new TextEncoder();
const GW = 200, GH = 120, MAXW = 5, MAX_TEAM = 50;
const WORLD = 'canvas/world.json';
const hexOk = v => /^#[0-9a-f]{6}$/i.test(String(v));
const cut = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const getJ = async (R, k, d) => { try { const o = await R.get(k); return o ? await o.json() : d; } catch (e) { return d; } };
const putJ = (R, k, v) => R.put(k, JSON.stringify(v), { httpMetadata: { contentType: 'application/json' } });

async function hashPw(pw, salt) {
  const key = await crypto.subtle.importKey('raw', TE.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: TE.encode(salt), iterations: 100000 }, key, 256);
  return hex(bits);
}
const rnd = n => hex(crypto.getRandomValues(new Uint8Array(n)));

// ---- Google sign-in (same GOOGLE_CLIENT_ID variable as your comics app)
const TD = new TextDecoder();
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
async function verifyGoogle(tok, env) {
  const [h, p, sig] = tok.split('.');
  if (!sig) throw 0;
  const head = JSON.parse(TD.decode(unb64u(h))), pl = JSON.parse(TD.decode(unb64u(p)));
  const jw = await (await fetch('https://www.googleapis.com/oauth2/v3/certs', { cf: { cacheTtl: 3600, cacheEverything: true } })).json();
  const jwk = jw.keys.find(k => k.kid === head.kid);
  if (!jwk) throw 0;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, unb64u(sig), TE.encode(h + '.' + p));
  if (!ok || pl.aud !== env.GOOGLE_CLIENT_ID || !/^(https:\/\/)?accounts\.google\.com$/.test(pl.iss) || pl.exp * 1000 < Date.now()) throw 0;
  return { sub: pl.sub, email: (pl.email_verified === true || pl.email_verified === 'true') ? String(pl.email || '').toLowerCase() : '' };
}

// ---- notifications: saved in an inbox per player; emailed too if RESEND_API_KEY is set
// and the player opted in (at most one email per 10 minutes per player).
async function notify(R, env, ukey, item) {
  const k = 'canvas/n/' + ukey + '.json', d = await getJ(R, k, { items: [], seen: 0, mail: 0 });
  d.items = [item, ...(d.items || [])].slice(0, 30);
  const u = await getJ(R, 'canvas/u/' + ukey + '.json', null);
  if (u && u.email && u.emailOn && env.RESEND_API_KEY && Date.now() - (d.mail || 0) > 600000) {
    d.mail = Date.now();
    try {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: env.MAIL_FROM || 'Territory Canvas <onboarding@resend.dev>', to: [u.email], subject: 'Territory Canvas: ' + item.text.slice(0, 80), text: item.text + '\n\nOpen the canvas to respond.' })
      });
    } catch (e) {}
  }
  await putJ(R, k, d);
}

export async function onRequest({ request, env }) {
  const R = env.SYNC_BUCKET;
  if (!R) return J({ error: 'Server is missing the R2 binding named SYNC_BUCKET.' }, 503);
  // Cooldown scales with territory: MIN_TURN_MS (default 10s) for tiny owners, growing
  // 3s per square of land (shared per team member), capped at TURN_MS (default 5 min).
  const TURN = +env.TURN_MS || 300000, MINCD = +env.MIN_TURN_MS || 10000;
  const url = new URL(request.url), m = request.method;
  const path = url.pathname.replace(/^\/api\/canvas\/?/, '').split('/').filter(Boolean);
  const body = async () => { try { return await request.json(); } catch (e) { return {}; } };

  const loadWorld = async () => { const w = await getJ(R, WORLD, null) || {}; return { v: w.v || 0, cells: w.cells || {}, o: w.o || {}, t: w.t || {} }; };
  const saveWorld = async w => { w.v = (w.v || 0) + 1; await putJ(R, WORLD, w); };
  const userKey = n => 'canvas/u/' + n.toLowerCase() + '.json';
  const bearer = (request.headers.get('Authorization') || '').replace(/^Bearer /, '');
  const newSession = async u => { const t = rnd(24); await putJ(R, 'canvas/s/' + t, { u: u.key, t: Date.now() }); return t; };
  let user = null;
  if (/^[0-9a-f]{48}$/.test(bearer)) {
    const s = await getJ(R, 'canvas/s/' + bearer, null);
    if (s) user = await getJ(R, userKey(s.u), null);
  }
  const needUser = () => J({ error: 'Please log in first.' }, 401);
  const ownerKey = u => u.team ? 't:' + u.team : 'u:' + u.key;
  const landOf = (w, u) => { const k = ownerKey(u); let n = 0; for (const c in w.cells) if (w.cells[c][0] === k) n++; return n; };
  const cdFor = (w, u) => { const mem = u.team && w.t[u.team] ? w.t[u.team].m.length : 1; return Math.min(TURN, Math.round(MINCD + 3000 * landOf(w, u) / mem)); };
  const reachOf = (w, u) => u.team && w.t[u.team] ? Math.min(6, 1 + Math.floor(w.t[u.team].m.length / 2)) : 1;
  const power = (w, u) => u.team && w.t[u.team] ? Math.min(8, 1 + Math.floor(w.t[u.team].m.length / 2)) : 1;
  const display = (w, u) => u.team && w.t[u.team] ? w.t[u.team].n : (u.territory || u.name);
  const meInfo = (w, u) => ({ name: u.name, key: u.key, color: u.color, territory: u.territory || '', team: u.team || '', teamName: u.team && w.t[u.team] ? w.t[u.team].n : '', owner: ownerKey(u), last: u.last || 0, next: u.next || 0, cd: cdFor(w, u), land: landOf(w, u), email: !!u.email, emailOn: !!u.emailOn, reach: reachOf(w, u), power: power(w, u), turnMs: TURN, now: Date.now() });

  // ---- public world state
  if (m === 'GET' && path[0] === 'state') {
    const w = await loadWorld();
    if (+url.searchParams.get('since') === w.v && w.v) return J({ same: 1, now: Date.now() });
    return J({ ...w, w: GW, h: GH, now: Date.now() });
  }

  if (m === 'GET' && path[0] === 'config') return J({ clientId: env.GOOGLE_CLIENT_ID || '' });

  // ---- Google sign-in: first time needs a username; after that it logs straight in
  if (m === 'POST' && path[0] === 'google') {
    if (!env.GOOGLE_CLIENT_ID) return J({ error: 'Google sign-in is not set up (missing GOOGLE_CLIENT_ID).' }, 503);
    const b = await body(); let g;
    try { g = await verifyGoogle(String(b.credential || ''), env); } catch (e) { return J({ error: 'Google sign-in failed. Try again.' }, 401); }
    const lk = 'canvas/g/' + g.sub + '.json', link = await getJ(R, lk, null);
    let u = link ? await getJ(R, userKey(link.u), null) : null;
    if (!u) {
      const name = cut(b.username, 20);
      if (!name) return J({ need: 'username' });
      if (!/^[A-Za-z0-9_]{3,20}$/.test(name)) return J({ error: 'Username: 3-20 letters, numbers or _.', need: 'username' }, 400);
      if (await R.head(userKey(name))) return J({ error: 'That username is taken.', need: 'username' }, 409);
      u = { key: name.toLowerCase(), name, salt: '', hash: '', color: hexOk(b.color) ? b.color : '#e74c3c', territory: cut(b.territory, 24), team: '', last: 0, created: Date.now(), email: g.email, emailOn: !!g.email, sub: g.sub };
      await putJ(R, userKey(name), u); await putJ(R, lk, { u: u.key });
    } else if (g.email && u.email !== g.email) { u.email = g.email; await putJ(R, userKey(u.name), u); }
    return J({ token: await newSession(u), me: meInfo(await loadWorld(), u) });
  }

  // ---- notifications inbox + email opt-in
  if (path[0] === 'inbox') {
    if (!user) return needUser();
    const k = 'canvas/n/' + user.key + '.json', d = await getJ(R, k, { items: [], seen: 0, mail: 0 });
    if (m === 'POST' && path[1] === 'seen') { d.seen = Date.now(); await putJ(R, k, d); return J({ ok: 1 }); }
    return J({ items: d.items || [], seen: d.seen || 0, unseen: (d.items || []).filter(i => i.t > (d.seen || 0)).length });
  }
  if (m === 'POST' && path[0] === 'settings') {
    if (!user) return needUser();
    const b = await body();
    user.emailOn = !!b.emailOn && !!user.email;
    await putJ(R, userKey(user.name), user);
    return J({ ok: 1, emailOn: user.emailOn });
  }

  // ---- accounts
  if (m === 'POST' && path[0] === 'register') {
    const b = await body(), name = cut(b.username, 20), pw = String(b.password || '');
    if (!/^[A-Za-z0-9_]{3,20}$/.test(name)) return J({ error: 'Username: 3-20 letters, numbers or _.' }, 400);
    if (pw.length < 6 || pw.length > 100) return J({ error: 'Password must be 6-100 characters.' }, 400);
    if (await R.head(userKey(name))) return J({ error: 'That username is taken.' }, 409);
    const salt = rnd(16);
    const u = { key: name.toLowerCase(), name, salt, hash: await hashPw(pw, salt), color: hexOk(b.color) ? b.color : '#e74c3c', territory: cut(b.territory, 24), team: '', last: 0, created: Date.now() };
    await putJ(R, userKey(name), u);
    const w = await loadWorld();
    return J({ token: await newSession(u), me: meInfo(w, u) });
  }
  if (m === 'POST' && path[0] === 'login') {
    const b = await body(), name = cut(b.username, 20);
    const u = /^[A-Za-z0-9_]{3,20}$/.test(name) ? await getJ(R, userKey(name), null) : null;
    if (!u || (await hashPw(String(b.password || ''), u.salt)) !== u.hash) return J({ error: 'Wrong username or password.' }, 401);
    return J({ token: await newSession(u), me: meInfo(await loadWorld(), u) });
  }
  if (m === 'POST' && path[0] === 'logout') {
    if (/^[0-9a-f]{48}$/.test(bearer)) await R.delete('canvas/s/' + bearer);
    return J({ ok: 1 });
  }
  if (m === 'GET' && path[0] === 'me') {
    if (!user) return needUser();
    return J(meInfo(await loadWorld(), user));
  }

  // ---- teams (members pool their turns: more members = more squares per turn)
  if (m === 'POST' && path[0] === 'team') {
    if (!user) return needUser();
    const w = await loadWorld(), b = await body();
    const moveSolo = id => {   // your solo land joins the team
      const from = 'u:' + user.key, to = 't:' + id;
      for (const k in w.cells) if (w.cells[k][0] === from) w.cells[k][0] = to;
      delete w.o[from];
    };
    if (path[1] === 'create' || path[1] === 'join') {
      if (user.team) return J({ error: 'Leave your current team first.' }, 400);
      let id;
      if (path[1] === 'create') {
        const name = cut(b.name, 24);
        id = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 24);
        if (name.length < 3 || id.length < 3) return J({ error: 'Team name needs at least 3 letters or numbers.' }, 400);
        if (w.t[id]) return J({ error: 'A team with that name already exists.' }, 409);
        w.t[id] = { n: name, c: hexOk(b.color) ? b.color : user.color, m: [user.name] };
      } else {
        id = String(b.id || '');
        if (!w.t[id]) return J({ error: 'That team no longer exists.' }, 404);
        if (w.t[id].m.length >= MAX_TEAM) return J({ error: 'That team is full.' }, 400);
        for (const mem of w.t[id].m.slice(0, 20)) await notify(R, env, mem.toLowerCase(), { type: 'team', text: user.name + ' joined your team ' + w.t[id].n + '. Your turns just got stronger!', t: Date.now() });
        w.t[id].m.push(user.name);
      }
      moveSolo(id);
      w.o['t:' + id] = { n: w.t[id].n, c: w.t[id].c };
      user.team = id;
    } else if (path[1] === 'leave') {
      if (!user.team) return J({ error: 'You are not in a team.' }, 400);
      const t = w.t[user.team];
      if (t) {
        t.m = t.m.filter(x => x !== user.name);
        if (!t.m.length) {   // an empty team dissolves and its land is released
          const k = 't:' + user.team;
          for (const c in w.cells) if (w.cells[c][0] === k) delete w.cells[c];
          delete w.o[k]; delete w.t[user.team];
        }
      }
      user.team = '';
    } else return J({ error: 'Not found.' }, 404);
    await saveWorld(w); await putJ(R, userKey(user.name), user);
    return J({ ok: 1, me: meInfo(w, user) });
  }

  // ---- take a turn
  if (m === 'POST' && path[0] === 'turn') {
    if (!user) return needUser();
    const b = await body(), now = Date.now();
    if (now < (user.next || 0)) return J({ error: 'Your next turn is not ready yet.', next: user.next }, 429);
    const action = b.action;
    if (!['claim', 'wall', 'attack'].includes(action)) return J({ error: 'Bad action.' }, 400);
    const w = await loadWorld(), key = ownerKey(user), p = power(w, user);
    const seen = new Set(), targets = [];
    for (const c of (Array.isArray(b.cells) ? b.cells : []).slice(0, p)) {
      const x = Math.trunc(+c[0]), y = Math.trunc(+c[1]);
      if (!(x >= 0 && x < GW && y >= 0 && y < GH) || seen.has(x + ',' + y)) continue;
      seen.add(x + ',' + y); targets.push([x, y]);
    }
    if (!targets.length) return J({ error: 'Pick at least one square.' }, 400);
    const mine = k => w.cells[k] && w.cells[k][0] === key;
    let hasAny = false; for (const k in w.cells) if (w.cells[k][0] === key) { hasAny = true; break; }
    const rch = reachOf(w, user);   // how many squares away from your land you can act (team bonus)
    const adj = (x, y) => {
      for (let dx = -rch; dx <= rch; dx++) for (let dy = -(rch - Math.abs(dx)); dy <= rch - Math.abs(dx); dy++)
        if ((dx || dy) && mine((x + dx) + ',' + (y + dy))) return true;
      return false;
    };
    let done = 0, captured = 0, last = '';
    const victims = {};
    for (const [x, y] of targets) {
      const k = x + ',' + y, c = w.cells[k];
      if (action === 'claim') {
        if (c) { last = 'That square is already taken.'; continue; }
        if (hasAny && !adj(x, y)) { last = 'Too far: you can claim up to ' + rch + ' square' + (rch > 1 ? 's' : '') + ' away from your territory. Join a team to reach further.'; continue; }
        w.cells[k] = [key, 0]; hasAny = true; done++;
      } else if (action === 'wall') {
        if (!c || c[0] !== key) { last = 'You can only build walls on your own squares.'; continue; }
        if (c[1] >= MAXW) { last = 'That wall is already at maximum level.'; continue; }
        c[1]++; done++;
      } else {
        if (!c || c[0] === key) { last = 'Attack a square owned by someone else.'; continue; }
        if (!adj(x, y)) { last = 'Too far: you can attack up to ' + rch + ' square' + (rch > 1 ? 's' : '') + ' away from your territory.'; continue; }
        const pv = c[0]; victims[pv] = victims[pv] || { hit: 0, lost: 0 };
        if (c[1] > 0) { c[1]--; victims[pv].hit++; } else { w.cells[k] = [key, 0]; captured++; victims[pv].lost++; }
        done++;
      }
    }
    if (!done) return J({ error: last || 'Nothing happened.' }, 400);
    w.o[key] = { n: display(w, user), c: user.team && w.t[user.team] ? w.t[user.team].c : user.color };
    user.last = now; user.next = now + cdFor(w, user);
    await saveWorld(w); await putJ(R, userKey(user.name), user);
    const who = user.name + (user.team && w.t[user.team] ? ' (' + w.t[user.team].n + ')' : '');
    for (const ok in victims) {
      const v = victims[ok];
      const text = who + ' attacked your territory: ' + [v.lost && v.lost + ' square' + (v.lost > 1 ? 's' : '') + ' captured', v.hit && v.hit + ' wall hit' + (v.hit > 1 ? 's' : '')].filter(Boolean).join(', ') + '.';
      const keys = ok.startsWith('t:') ? ((w.t[ok.slice(2)] || { m: [] }).m.map(x => x.toLowerCase())) : [ok.slice(2)];
      for (const k of keys.slice(0, 20)) await notify(R, env, k, { type: 'atk', text, t: Date.now() });
    }
    return J({ ok: 1, done, captured, me: meInfo(w, user) });
  }

  return J({ error: 'Not found.' }, 404);
}
