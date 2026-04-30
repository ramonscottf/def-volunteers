/**
 * volunteers-api Worker
 * Unified backend for the DEF Volunteer Hub.
 * https://volunteers.daviskids.org
 *
 * Native Workers ESM — no build step. Single file for easy inspection and deploy.
 */

import { appendVolunteerRow, updateVolunteerRow, rebuildAllSheets, ensureHeaders, rebuildEventSheet } from './sheets.js';

// ---------- Config ----------
const ALLOWED_ORIGINS = new Set([
  'https://daviskids.org',
  'https://www.daviskids.org',
  'https://childspree.org',
  'https://childspree.pages.dev',
  'https://def-site.pages.dev',
  'https://gala.daviskids.org',
]);

const MSAL_TENANT = '3d9cf274-547e-4af5-8dde-01a636e0b607';
const MSAL_AUDIENCE = 'ddf5d2a5-b2f2-4661-943f-c25fcc69833f';
const SESSION_COOKIE = 'dv_admin_session';
const SESSION_TTL_SECS = 8 * 3600;

// ---------- Tiny helpers ----------
const json = (data, init = {}) =>
  new Response(JSON.stringify(data), {
    ...init,
    headers: { 'content-type': 'application/json', ...(init.headers || {}) },
  });

const err = (code, message, extra = {}) =>
  json({ error: message, ...extra }, { status: code });

const nanoid = (n = 14) => {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  let s = '';
  for (let i = 0; i < n; i++) s += chars[buf[i] % chars.length];
  return s;
};

const corsHeaders = (origin) => {
  const allow = origin && ALLOWED_ORIGINS.has(origin) ? origin : 'https://daviskids.org';
  return {
    'access-control-allow-origin': allow,
    'access-control-allow-credentials': 'true',
    'access-control-allow-methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'access-control-allow-headers': 'content-type, authorization',
    'vary': 'Origin',
  };
};

const withCors = (res, origin) => {
  const h = new Headers(res.headers);
  const cors = corsHeaders(origin);
  for (const [k, v] of Object.entries(cors)) h.set(k, v);
  return new Response(res.body, { status: res.status, headers: h });
};

// ---------- Router ----------
class Router {
  constructor() { this.routes = []; }
  add(method, pattern, handler) { this.routes.push({ method, pattern, handler }); return this; }
  get(p, h) { return this.add('GET', p, h); }
  post(p, h) { return this.add('POST', p, h); }
  patch(p, h) { return this.add('PATCH', p, h); }
  delete(p, h) { return this.add('DELETE', p, h); }

  match(method, path) {
    for (const r of this.routes) {
      if (r.method !== method) continue;
      const params = matchPath(r.pattern, path);
      if (params) return { handler: r.handler, params };
    }
    return null;
  }
}

function matchPath(pattern, path) {
  const pp = pattern.split('/').filter(Boolean);
  const ap = path.split('/').filter(Boolean);
  if (pp.length !== ap.length) return null;
  const params = {};
  for (let i = 0; i < pp.length; i++) {
    if (pp[i].startsWith(':')) params[pp[i].slice(1)] = decodeURIComponent(ap[i]);
    else if (pp[i] !== ap[i]) return null;
  }
  return params;
}

// ---------- Session cookie (HMAC-signed) ----------
async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return base64UrlEncode(new Uint8Array(sig));
}

async function hmacVerify(secret, data, sig) {
  const expected = await hmacSign(secret, data);
  return timingSafeEqual(expected, sig);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function base64UrlEncode(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function createSession(env, payload) {
  const body = { ...payload, iat: Date.now(), exp: Date.now() + SESSION_TTL_SECS * 1000 };
  const data = base64UrlEncode(new TextEncoder().encode(JSON.stringify(body)));
  const sig = await hmacSign(env.SESSION_SECRET, data);
  return `${data}.${sig}`;
}

async function readSession(env, token) {
  if (!token) return null;
  const [data, sig] = token.split('.');
  if (!data || !sig) return null;
  if (!(await hmacVerify(env.SESSION_SECRET, data, sig))) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(data)));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function setSessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; Path=/; Domain=.daviskids.org; Secure; HttpOnly; SameSite=None; Max-Age=${SESSION_TTL_SECS}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; Domain=.daviskids.org; Secure; HttpOnly; SameSite=None; Max-Age=0`;
}

function readCookie(req, name) {
  const header = req.headers.get('cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return rest.join('=');
  }
  return null;
}

// ---------- MSAL ID token verification ----------
let jwksCache = null;
let jwksCacheAt = 0;
const JWKS_TTL = 12 * 3600 * 1000;

async function getJwks() {
  const now = Date.now();
  if (jwksCache && now - jwksCacheAt < JWKS_TTL) return jwksCache;
  const res = await fetch(`https://login.microsoftonline.com/${MSAL_TENANT}/discovery/v2.0/keys`);
  if (!res.ok) throw new Error('jwks fetch failed');
  jwksCache = await res.json();
  jwksCacheAt = now;
  return jwksCache;
}

async function verifyMsalIdToken(idToken) {
  const [hb64, pb64, sb64] = idToken.split('.');
  if (!hb64 || !pb64 || !sb64) throw new Error('malformed token');

  const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(hb64)));
  const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(pb64)));

  // Basic claim checks
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw new Error('token expired');
  if (payload.nbf && payload.nbf > now + 30) throw new Error('token not yet valid');
  if (payload.aud && payload.aud !== MSAL_AUDIENCE) throw new Error('wrong audience');
  if (payload.tid && payload.tid !== MSAL_TENANT) throw new Error('wrong tenant');

  // Signature verification
  const jwks = await getJwks();
  const key = jwks.keys.find((k) => k.kid === header.kid);
  if (!key) throw new Error('unknown signing key');

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    { kty: key.kty, n: key.n, e: key.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const signed = new TextEncoder().encode(`${hb64}.${pb64}`);
  const sig = base64UrlDecode(sb64);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, sig, signed);
  if (!ok) throw new Error('bad signature');

  return payload;
}

// ---------- Auth middleware ----------
async function requireAdmin(req, env) {
  const token = readCookie(req, SESSION_COOKIE);
  const session = await readSession(env, token);
  if (!session) return null;
  const allowed = (env.ADMIN_EMAILS || '').split(',').map((s) => s.trim().toLowerCase());
  if (!allowed.includes(session.email.toLowerCase())) return null;
  return session;
}

function roleForEmail(env, email) {
  const allowed = (env.ADMIN_EMAILS || '').split(',').map((s) => s.trim().toLowerCase());
  return allowed.includes((email || '').toLowerCase()) ? 'admin' : 'unknown';
}

// ---------- Volunteer validation ----------
// NOTE: phone is required at the form layer (gala-volunteer.html, volunteer.html hub,
// forekids-volunteer.html, childspree volunteer form). It's left optional here so
// (a) backfill of historical rows that may lack phone doesn't fail, and
// (b) mirror calls from legacy backends remain forgiving.
const REQUIRED_VOL_FIELDS = ['event_slug', 'first_name', 'last_name', 'email'];

function validateVolunteer(body) {
  const errors = [];
  for (const f of REQUIRED_VOL_FIELDS) {
    if (!body[f] || typeof body[f] !== 'string' || !body[f].trim()) {
      errors.push(`${f} is required`);
    }
  }
  if (body.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) {
    errors.push('invalid email');
  }
  if (body.phone && !/^[\d\-\(\)\s\+]{7,}$/.test(body.phone)) {
    errors.push('invalid phone');
  }
  return errors;
}

// ---------- Notification helpers ----------
async function sendEmail(env, { to, subject, text, html, from }) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'authorization': `Bearer ${env.RESEND_API_KEY}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      from: from || 'Davis Education Foundation <noreply@daviskids.org>',
      to: [to],
      subject,
      text,
      html: html || undefined,
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`resend error ${res.status}: ${body}`);
  }
  return res.json();
}

async function sendSms(env, { to, body }) {
  const url = `https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_ACCOUNT_SID}/Messages.json`;
  const form = new URLSearchParams({ From: env.TWILIO_FROM, To: to, Body: body });
  const auth = btoa(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`);
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'authorization': `Basic ${auth}`, 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`twilio error ${res.status}: ${text}`);
  }
  return res.json();
}

function renderTemplate(template, vars) {
  return template.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, k) => vars[k] ?? '');
}

// ---------- Routes ----------
const router = new Router();

// Health
router.get('/', () => json({ service: 'volunteers-api', status: 'ok', version: '1.0.0' }));
router.get('/api/health', () => json({ ok: true, ts: new Date().toISOString() }));

// -- Public --
router.get('/api/events', async (req, env) => {
  const rows = await env.DB.prepare(
    `SELECT slug, name, tagline, event_date, venue, signup_url, accent_color,
            display_order, capacity, config, active, show_on_hub
       FROM events WHERE active = 1 AND show_on_hub = 1
       ORDER BY display_order ASC, event_date ASC`
  ).all();
  return json({ events: rows.results.map(parseEventConfig) });
});

router.get('/api/events/:slug', async (req, env, params) => {
  const row = await env.DB.prepare(`SELECT * FROM events WHERE slug = ?`)
    .bind(params.slug).first();
  if (!row) return err(404, 'event not found');
  return json({ event: parseEventConfig(row) });
});

router.get('/api/capacity/:slug', async (req, env, params) => {
  const evt = await env.DB.prepare(`SELECT slug, config FROM events WHERE slug = ?`)
    .bind(params.slug).first();
  if (!evt) return err(404, 'event not found');
  const counts = await env.DB.prepare(
    `SELECT location, role, shift, COUNT(*) AS n FROM volunteers
      WHERE event_slug = ? AND status != 'cancelled'
      GROUP BY location, role, shift`
  ).bind(params.slug).all();
  return json({
    slug: params.slug,
    config: evt.config ? JSON.parse(evt.config) : null,
    counts: counts.results,
  });
});

router.post('/api/volunteers', async (req, env) => {
  let body;
  try { body = await req.json(); } catch { return err(400, 'invalid JSON'); }
  const errors = validateVolunteer(body);
  if (errors.length) return err(400, 'validation failed', { errors });

  const evt = await env.DB.prepare(`SELECT slug, active FROM events WHERE slug = ?`)
    .bind(body.event_slug).first();
  if (!evt || !evt.active) return err(400, 'unknown or inactive event');

  const upsert = body.upsert === true;
  const isMirror = body.source === 'mirror';
  const email = body.email.trim().toLowerCase();
  const now = new Date().toISOString();

  // Extract event_data (anything beyond known columns)
  const known = new Set([
    'event_slug', 'first_name', 'last_name', 'email', 'phone', 'organization',
    'group_type', 'group_size', 'shirt_size', 'role', 'location', 'shift',
    'arrival_time', 'early_arrival', 'experience', 'hear_about', 'sms_opt_in', 'notes',
    'status', 'created_at', 'upsert', 'source',
  ]);
  const extra = {};
  for (const k of Object.keys(body)) if (!known.has(k)) extra[k] = body[k];

  // Upsert: find existing row by (email, event_slug)
  let existing = null;
  if (upsert) {
    existing = await env.DB.prepare(
      `SELECT id FROM volunteers WHERE event_slug = ? AND lower(email) = ?`
    ).bind(body.event_slug, email).first();
  }

  let id;
  let action;
  if (existing) {
    id = existing.id;
    action = 'updated';
    await env.DB.prepare(
      `UPDATE volunteers SET
        first_name = ?, last_name = ?, phone = ?, organization = ?,
        group_type = ?, group_size = ?, shirt_size = ?, role = ?, location = ?,
        shift = ?, arrival_time = ?, early_arrival = ?, experience = ?,
        hear_about = ?, sms_opt_in = ?, notes = ?,
        status = COALESCE(?, status),
        event_data = ?, updated_at = ?
       WHERE id = ?`
    ).bind(
      body.first_name.trim(), body.last_name.trim(),
      body.phone || null, body.organization || null,
      body.group_type || 'individual', body.group_size || 1, body.shirt_size || null,
      body.role || null, body.location || null, body.shift || null,
      body.arrival_time || null, body.early_arrival ? 1 : 0,
      body.experience || null, body.hear_about || null,
      body.sms_opt_in ? 1 : 0, body.notes || null,
      body.status || null,
      Object.keys(extra).length ? JSON.stringify(extra) : null,
      now, id,
    ).run();
  } else {
    id = nanoid();
    action = 'created';
    const status = body.status || 'pending';
    const createdAt = body.created_at || now;
    await env.DB.prepare(
      `INSERT INTO volunteers
        (id, event_slug, first_name, last_name, email, phone, organization,
         group_type, group_size, shirt_size, role, location, shift,
         arrival_time, early_arrival, experience, hear_about, sms_opt_in, notes,
         status, event_data, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      id, body.event_slug, body.first_name.trim(), body.last_name.trim(),
      email, body.phone || null, body.organization || null,
      body.group_type || 'individual', body.group_size || 1, body.shirt_size || null,
      body.role || null, body.location || null, body.shift || null,
      body.arrival_time || null, body.early_arrival ? 1 : 0,
      body.experience || null, body.hear_about || null,
      body.sms_opt_in ? 1 : 0, body.notes || null,
      status,
      Object.keys(extra).length ? JSON.stringify(extra) : null,
      createdAt, now,
    ).run();
  }

  // Fire-and-forget confirmation email (skip for mirrored signups — origin sends its own)
  if (!isMirror && action === 'created' && env.RESEND_API_KEY) {
    const evtRow = await env.DB.prepare(`SELECT name, event_date, venue FROM events WHERE slug = ?`)
      .bind(body.event_slug).first();
    if (evtRow) {
      const subject = `Thanks for volunteering — ${evtRow.name}`;
      const text = `Hi ${body.first_name},\n\nThank you for signing up to volunteer for ${evtRow.name} on ${evtRow.event_date} at ${evtRow.venue}.\n\nWe'll send more details as the event approaches.\n\n— Davis Education Foundation`;
      try { await sendEmail(env, { to: email, subject, text }); } catch (e) { console.error('confirm email failed', e); }
    }
  }

  // Fire-and-forget Google Sheets sync (don't block response)
  if (env.GOOGLE_SERVICE_ACCOUNT_JSON && env.GALA_VOLUNTEERS_SHEET_ID) {
    try {
      const fullVol = await env.DB.prepare(`SELECT * FROM volunteers WHERE id = ?`).bind(id).first();
      if (action === 'updated') {
        await updateVolunteerRow(env, fullVol);
      } else {
        await appendVolunteerRow(env, fullVol);
      }
    } catch (e) { console.error('sheets sync failed', e); }
  }

  return json({ ok: true, id, action }, { status: action === 'created' ? 201 : 200 });
});

// -- Auth --
router.post('/api/auth/session', async (req, env) => {
  let body;
  try { body = await req.json(); } catch { return err(400, 'invalid JSON'); }
  if (!body.id_token) return err(400, 'id_token required');

  let claims;
  try { claims = await verifyMsalIdToken(body.id_token); }
  catch (e) { return err(401, 'invalid token', { detail: e.message }); }

  const email = (claims.preferred_username || claims.email || '').toLowerCase();
  if (!email) return err(401, 'no email in token');
  if (roleForEmail(env, email) !== 'admin') return err(403, 'not authorized');

  const token = await createSession(env, {
    email, name: claims.name || email, role: 'admin',
  });
  return new Response(JSON.stringify({ ok: true, email, role: 'admin' }), {
    status: 200,
    headers: { 'content-type': 'application/json', 'set-cookie': setSessionCookie(token) },
  });
});

// -- Magic link auth (passwordless email login) --
router.post('/api/auth/magic-link/request', async (req, env) => {
  let body;
  try { body = await req.json(); } catch { return err(400, 'invalid JSON'); }
  const email = (body.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) return err(400, 'valid email required');

  // Always return success — don't leak whether an email is on the allowlist
  if (roleForEmail(env, email) !== 'admin') {
    return json({ ok: true });
  }

  // Sign a short-lived (15 min) magic link token using the same HMAC pattern as sessions
  const linkPayload = {
    email,
    purpose: 'magic-link',
    iat: Date.now(),
    exp: Date.now() + 15 * 60 * 1000,
  };
  const data = base64UrlEncode(new TextEncoder().encode(JSON.stringify(linkPayload)));
  const sig = await hmacSign(env.SESSION_SECRET, data);
  const linkToken = `${data}.${sig}`;

  const origin = new URL(req.url).origin;
  // Magic link points back at the dashboard's origin so the cookie set on the API origin is shared
  const verifyUrl = `${origin}/api/auth/magic-link/verify?token=${encodeURIComponent(linkToken)}`;

  if (env.RESEND_API_KEY) {
    try {
      // Use mail.fosterlabs.org pipe — verified gala@daviskids.org sender, proven reliable
      const mailRes = await fetch('https://mail.fosterlabs.org/send', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer SkippyMail2026',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          to: email,
          from: 'Davis Education Foundation <gala@daviskids.org>',
          replyTo: 'smiggin@dsdmail.net',
          subject: 'Your DEF Volunteer Admin sign-in link',
          text:
`Hi,

Click this link to sign in to the DEF Volunteer Admin dashboard:

${verifyUrl}

This link expires in 15 minutes and can only be used once. If you didn't request this, you can ignore this email.

— Davis Education Foundation`,
          html: `<div style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:520px;margin:0 auto;padding:24px">
<h2 style="color:#0d1b3d;margin:0 0 16px;font-family:Georgia,serif;font-weight:400">Your sign-in link</h2>
<p style="color:#1a1a1a;line-height:1.5">Click the button below to sign in to the DEF Volunteer Admin dashboard.</p>
<p style="margin:28px 0">
  <a href="${verifyUrl}" style="background:#0d1b3d;color:#fff;text-decoration:none;padding:14px 28px;border-radius:6px;font-weight:600;display:inline-block">Sign in to Volunteer Admin</a>
</p>
<p style="color:#5a6276;font-size:13px;line-height:1.5">This link expires in 15 minutes. If you didn't request it, you can ignore this email.</p>
<p style="color:#5a6276;font-size:13px;line-height:1.5;word-break:break-all">Or paste this URL into your browser:<br>${verifyUrl}</p>
<hr style="border:0;border-top:1px solid #d8dde6;margin:28px 0 16px">
<p style="color:#5a6276;font-size:12px">Davis Education Foundation</p>
</div>`,
        }),
      });
      if (!mailRes.ok) {
        const errText = await mailRes.text();
        console.error('magic link email failed', mailRes.status, errText);
        return err(500, 'failed to send sign-in email', { detail: `mail ${mailRes.status}` });
      }
    } catch (e) {
      console.error('magic link email failed', e);
      return err(500, 'failed to send sign-in email', { detail: String(e.message || e) });
    }
  } else {
    console.log('DEV: magic link =', verifyUrl);
  }

  return json({ ok: true });
});

router.get('/api/auth/magic-link/verify', async (req, env) => {
  const url = new URL(req.url);
  const token = url.searchParams.get('token');
  if (!token) return new Response('Missing token', { status: 400 });

  const [data, sig] = token.split('.');
  if (!data || !sig) return new Response('Invalid token', { status: 400 });
  if (!(await hmacVerify(env.SESSION_SECRET, data, sig))) {
    return new Response('Invalid or tampered link. Request a new sign-in link.', { status: 401 });
  }

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(data)));
  } catch {
    return new Response('Malformed token', { status: 400 });
  }
  if (payload.purpose !== 'magic-link') return new Response('Wrong token type', { status: 400 });
  if (!payload.exp || payload.exp < Date.now()) {
    return new Response('This link has expired. Request a new one.', { status: 401 });
  }
  if (roleForEmail(env, payload.email) !== 'admin') {
    return new Response('This email is no longer authorized.', { status: 403 });
  }

  const sessionToken = await createSession(env, {
    email: payload.email,
    name: payload.email,
    role: 'admin',
    method: 'magic-link',
  });

  // Redirect to the dashboard with the cookie set
  const dashboardUrl = 'https://daviskids.org/volunteer-admin/';
  return new Response(null, {
    status: 302,
    headers: {
      'location': dashboardUrl,
      'set-cookie': setSessionCookie(sessionToken),
    },
  });
});

router.post('/api/auth/logout', () =>
  new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'content-type': 'application/json', 'set-cookie': clearSessionCookie() },
  })
);

router.get('/api/auth/role', async (req, env) => {
  const session = await requireAdmin(req, env);
  if (!session) return json({ role: 'unknown' });
  return json({ role: 'admin', email: session.email, name: session.name });
});

// -- Admin volunteers --
router.get('/api/admin/volunteers', async (req, env) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');
  const url = new URL(req.url);
  const event = url.searchParams.get('event');
  const status = url.searchParams.get('status');
  const role = url.searchParams.get('role');
  const location = url.searchParams.get('location');
  const search = url.searchParams.get('search');
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '500'), 2000);

  const conds = [];
  const binds = [];
  if (event) { conds.push('event_slug = ?'); binds.push(event); }
  if (status) { conds.push('status = ?'); binds.push(status); }
  if (role) { conds.push('role = ?'); binds.push(role); }
  if (location) { conds.push('location = ?'); binds.push(location); }
  if (search) {
    conds.push('(LOWER(first_name) LIKE ? OR LOWER(last_name) LIKE ? OR LOWER(email) LIKE ? OR LOWER(organization) LIKE ?)');
    const s = `%${search.toLowerCase()}%`;
    binds.push(s, s, s, s);
  }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const sql = `SELECT * FROM volunteers ${where} ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  const rows = await env.DB.prepare(sql).bind(...binds).all();
  return json({ volunteers: rows.results, count: rows.results.length });
});

router.get('/api/admin/volunteers/:id', async (req, env, params) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');
  const row = await env.DB.prepare(`SELECT * FROM volunteers WHERE id = ?`).bind(params.id).first();
  if (!row) return err(404, 'not found');
  return json({ volunteer: row });
});

router.patch('/api/admin/volunteers/:id', async (req, env, params) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');
  let body;
  try { body = await req.json(); } catch { return err(400, 'invalid JSON'); }

  const allowed = ['status', 'role', 'location', 'shift', 'notes', 'arrival_time', 'early_arrival', 'shirt_size'];
  const sets = [];
  const binds = [];
  for (const k of allowed) {
    if (k in body) {
      sets.push(`${k} = ?`);
      binds.push(typeof body[k] === 'boolean' ? (body[k] ? 1 : 0) : body[k]);
    }
  }
  if (!sets.length) return err(400, 'no fields to update');
  sets.push(`updated_at = datetime('now')`);

  binds.push(params.id);
  await env.DB.prepare(`UPDATE volunteers SET ${sets.join(', ')} WHERE id = ?`).bind(...binds).run();
  const row = await env.DB.prepare(`SELECT * FROM volunteers WHERE id = ?`).bind(params.id).first();

  // Fire-and-forget Google Sheets update (don't block response)
  if (env.GOOGLE_SERVICE_ACCOUNT_JSON && env.GALA_VOLUNTEERS_SHEET_ID && row) {
    try { await updateVolunteerRow(env, row); }
    catch (e) { console.error('sheets update failed', e); }
  }

  return json({ ok: true, volunteer: row });
});

router.delete('/api/admin/volunteers/:id', async (req, env, params) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');
  await env.DB.prepare(`UPDATE volunteers SET status = 'cancelled', updated_at = datetime('now') WHERE id = ?`)
    .bind(params.id).run();

  // Sync the cancellation to the Sheet
  if (env.GOOGLE_SERVICE_ACCOUNT_JSON && env.GALA_VOLUNTEERS_SHEET_ID) {
    try {
      const row = await env.DB.prepare(`SELECT * FROM volunteers WHERE id = ?`).bind(params.id).first();
      if (row) await updateVolunteerRow(env, row);
    } catch (e) { console.error('sheets cancel sync failed', e); }
  }

  return json({ ok: true });
});

// Hard delete — removes the record entirely from D1 and clears the corresponding row in the Sheet
router.delete('/api/admin/volunteers/:id/hard', async (req, env, params) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');

  // Snapshot before delete so we can clear the Sheet row by ID
  const row = await env.DB.prepare(`SELECT * FROM volunteers WHERE id = ?`).bind(params.id).first();
  if (!row) return err(404, 'not found');

  // Hard-remove from D1
  await env.DB.prepare(`DELETE FROM volunteers WHERE id = ?`).bind(params.id).run();

  // Clear the corresponding row in the Sheet (find by ID in column A, blank the row)
  if (env.GOOGLE_SERVICE_ACCOUNT_JSON && env.GALA_VOLUNTEERS_SHEET_ID) {
    try {
      // Sheets API can't easily delete a single row by ID; rebuild this event's tab from D1.
      await rebuildEventSheet(env, env.DB, row.event_slug);
    } catch (e) { console.error('sheets hard-delete sync failed', e); }
  }

  return json({ ok: true, deleted: row.id });
});

// -- Admin Sheets sync controls --
router.post('/api/admin/sheets/init', async (req, env) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');
  try {
    const result = await ensureHeaders(env);
    return json({ ok: true, result });
  } catch (e) {
    return err(500, 'init failed', { detail: e.message });
  }
});

router.post('/api/admin/sheets/rebuild', async (req, env) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');
  try {
    const result = await rebuildAllSheets(env, env.DB);
    return json({ ok: true, result });
  } catch (e) {
    return err(500, 'rebuild failed', { detail: e.message });
  }
});

// -- Admin stats --
router.get('/api/admin/stats', async (req, env) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');
  const byEvent = await env.DB.prepare(
    `SELECT event_slug, status, COUNT(*) AS n FROM volunteers GROUP BY event_slug, status`
  ).all();
  const totals = await env.DB.prepare(
    `SELECT COUNT(*) AS total, SUM(status = 'confirmed') AS confirmed,
            SUM(status = 'pending') AS pending, SUM(status = 'checked_in') AS checked_in,
            SUM(status = 'completed') AS completed, SUM(status = 'cancelled') AS cancelled
       FROM volunteers`
  ).first();
  return json({ totals, byEvent: byEvent.results });
});

router.get('/api/admin/person', async (req, env) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');
  const email = new URL(req.url).searchParams.get('email');
  if (!email) return err(400, 'email required');
  const rows = await env.DB.prepare(
    `SELECT id, event_slug, first_name, last_name, status, role, location, created_at
       FROM volunteers WHERE LOWER(email) = ? ORDER BY created_at DESC`
  ).bind(email.toLowerCase()).all();
  return json({ email, registrations: rows.results });
});

// -- Admin events --
router.post('/api/admin/events', async (req, env) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');
  const b = await req.json().catch(() => null);
  if (!b || !b.slug || !b.name) return err(400, 'slug and name required');
  await env.DB.prepare(
    `INSERT INTO events (slug, name, tagline, description, event_date, venue, signup_url,
                         hero_image, icon, accent_color, active, show_on_hub, capacity,
                         display_order, config)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    b.slug, b.name, b.tagline || null, b.description || null, b.event_date || null,
    b.venue || null, b.signup_url || `/volunteer/${b.slug}`, b.hero_image || null,
    b.icon || null, b.accent_color || '#1b2e5a', b.active ? 1 : 1, b.show_on_hub ? 1 : 1,
    b.capacity || null, b.display_order || 99,
    b.config ? JSON.stringify(b.config) : null,
  ).run();
  return json({ ok: true, slug: b.slug }, { status: 201 });
});

router.patch('/api/admin/events/:slug', async (req, env, params) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');
  const b = await req.json().catch(() => null);
  if (!b) return err(400, 'invalid JSON');
  const allowed = ['name', 'tagline', 'description', 'event_date', 'venue', 'signup_url',
                   'hero_image', 'icon', 'accent_color', 'active', 'show_on_hub',
                   'capacity', 'display_order'];
  const sets = [];
  const binds = [];
  for (const k of allowed) {
    if (k in b) {
      sets.push(`${k} = ?`);
      binds.push(typeof b[k] === 'boolean' ? (b[k] ? 1 : 0) : b[k]);
    }
  }
  if ('config' in b) { sets.push('config = ?'); binds.push(typeof b.config === 'string' ? b.config : JSON.stringify(b.config)); }
  if (!sets.length) return err(400, 'no fields to update');
  binds.push(params.slug);
  await env.DB.prepare(`UPDATE events SET ${sets.join(', ')} WHERE slug = ?`).bind(...binds).run();
  return json({ ok: true });
});

// -- Admin blasts --
router.post('/api/admin/blast/email', async (req, env) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');
  const b = await req.json().catch(() => null);
  if (!b || !b.subject || !b.message) return err(400, 'subject and message required');

  const conds = [];
  const binds = [];
  if (b.event) { conds.push('event_slug = ?'); binds.push(b.event); }
  if (b.status) { conds.push('status = ?'); binds.push(b.status); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')} AND email IS NOT NULL` : `WHERE email IS NOT NULL`;
  const recipients = (await env.DB.prepare(`SELECT first_name, last_name, email FROM volunteers ${where}`)
    .bind(...binds).all()).results;

  let sent = 0, failed = 0;
  for (const r of recipients) {
    const vars = { first_name: r.first_name, last_name: r.last_name, email: r.email };
    try {
      await sendEmail(env, {
        to: r.email,
        subject: renderTemplate(b.subject, vars),
        text: renderTemplate(b.message, vars),
      });
      sent++;
    } catch (e) { failed++; console.error('blast email fail', r.email, e.message); }
  }

  await env.DB.prepare(
    `INSERT INTO blasts (event_slug, type, subject, message, recipient_count, filter_snapshot, sent_by)
     VALUES (?, 'email', ?, ?, ?, ?, ?)`
  ).bind(b.event || null, b.subject, b.message, sent, JSON.stringify({ event: b.event, status: b.status }), session.email).run();

  return json({ ok: true, sent, failed, total: recipients.length });
});

router.post('/api/admin/blast/sms', async (req, env) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');
  const b = await req.json().catch(() => null);
  if (!b || !b.message) return err(400, 'message required');

  const conds = ['phone IS NOT NULL', 'sms_opt_in = 1'];
  const binds = [];
  if (b.event) { conds.push('event_slug = ?'); binds.push(b.event); }
  if (b.status) { conds.push('status = ?'); binds.push(b.status); }
  const where = `WHERE ${conds.join(' AND ')}`;
  const recipients = (await env.DB.prepare(`SELECT first_name, last_name, phone FROM volunteers ${where}`)
    .bind(...binds).all()).results;

  let sent = 0, failed = 0;
  for (const r of recipients) {
    const vars = { first_name: r.first_name, last_name: r.last_name };
    try {
      await sendSms(env, { to: r.phone, body: renderTemplate(b.message, vars) });
      sent++;
    } catch (e) { failed++; console.error('blast sms fail', r.phone, e.message); }
  }

  await env.DB.prepare(
    `INSERT INTO blasts (event_slug, type, message, recipient_count, filter_snapshot, sent_by)
     VALUES (?, 'sms', ?, ?, ?, ?)`
  ).bind(b.event || null, b.message, sent, JSON.stringify({ event: b.event, status: b.status }), session.email).run();

  return json({ ok: true, sent, failed, total: recipients.length });
});

// -- CSV export --
router.get('/api/admin/export', async (req, env) => {
  const session = await requireAdmin(req, env);
  if (!session) return err(401, 'unauthorized');
  const event = new URL(req.url).searchParams.get('event');
  const where = event ? 'WHERE event_slug = ?' : '';
  const binds = event ? [event] : [];
  const rows = (await env.DB.prepare(`SELECT * FROM volunteers ${where} ORDER BY created_at DESC`)
    .bind(...binds).all()).results;

  if (rows.length === 0) return new Response('No records\n', { headers: { 'content-type': 'text/csv' } });
  const cols = Object.keys(rows[0]);
  const escape = (v) => {
    if (v === null || v === undefined) return '';
    const s = String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [cols.join(',')];
  for (const r of rows) lines.push(cols.map((c) => escape(r[c])).join(','));
  const csv = lines.join('\n') + '\n';
  const filename = event ? `volunteers-${event}-${Date.now()}.csv` : `volunteers-${Date.now()}.csv`;
  return new Response(csv, {
    headers: {
      'content-type': 'text/csv; charset=utf-8',
      'content-disposition': `attachment; filename="${filename}"`,
    },
  });
});

// ---------- Helpers ----------
function parseEventConfig(row) {
  if (row.config && typeof row.config === 'string') {
    try { row.config = JSON.parse(row.config); } catch {}
  }
  return row;
}

// ---------- Main fetch handler ----------


export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('origin');

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    const route = router.match(request.method, url.pathname);
    if (!route) return withCors(err(404, 'not found'), origin);

    try {
      const res = await route.handler(request, env, route.params);
      return withCors(res, origin);
    } catch (e) {
      console.error('handler error', e);
      return withCors(err(500, 'server error', { detail: e.message }), origin);
    }
  },
};
