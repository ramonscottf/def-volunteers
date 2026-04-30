/**
 * Google Sheets sync for def-volunteers.
 *
 * Strategy:
 *   - One workbook (env.GALA_VOLUNTEERS_SHEET_ID), tab per event.
 *   - Volunteer.id is column A (the join key).
 *   - On new submission: append a row.
 *   - On status/role/location/notes update: find the row by ID, update it.
 *   - On hard delete: find row by ID, clear it (rare).
 *
 * All failures are caught + logged so D1 (source of truth) is never blocked.
 */

const SHEETS_API = 'https://sheets.googleapis.com/v4/spreadsheets';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';

// Column order (must match the header row in every tab)
// A   B          C       D     E    F     F     G   H    I        J     K       L     M     N     O
// ID  Submitted  Status  First Last Email Phone Org Role Location Shift Arrival Shirt Group Notes Updated
const HEADER = [
  'ID', 'Submitted', 'Status', 'First', 'Last', 'Email', 'Phone',
  'Org', 'Role', 'Location', 'Shift', 'Arrival', 'Shirt', 'Group', 'Notes', 'Updated',
];

const SLUG_TO_TAB = {
  'gala-2026': 'Gala',
  'forekids-2026': 'ForeKids',
  'child-spree-2026': 'Child Spree',
};

function tabFor(slug) {
  return SLUG_TO_TAB[slug] || slug;
}

function rowFromVolunteer(v) {
  return [
    v.id,
    (v.created_at || '').replace('T', ' ').substring(0, 19),
    v.status || 'pending',
    v.first_name || '',
    v.last_name || '',
    v.email || '',
    v.phone || '',
    v.organization || '',
    v.role || '',
    v.location || '',
    v.shift || '',
    v.arrival_time || '',
    v.shirt_size || '',
    v.group_type ? `${v.group_type}${v.group_size > 1 ? ` (${v.group_size})` : ''}` : '',
    v.notes || '',
    (v.updated_at || '').replace('T', ' ').substring(0, 19),
  ];
}

/* ----------------------------- public API ------------------------------- */

export async function appendVolunteerRow(env, volunteer) {
  const sheetId = env.GALA_VOLUNTEERS_SHEET_ID;
  if (!sheetId || !env.GOOGLE_SERVICE_ACCOUNT_JSON) return { skipped: true };

  const tab = tabFor(volunteer.event_slug);
  const token = await getAccessToken(env.GOOGLE_SERVICE_ACCOUNT_JSON);
  const range = `${tab}!A:P`;
  const url = `${SHEETS_API}/${sheetId}/values/${encodeURIComponent(range)}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`;

  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ values: [rowFromVolunteer(volunteer)] }),
  });
  if (!res.ok) throw new Error(`append ${res.status}: ${await res.text()}`);
  return { ok: true };
}

export async function updateVolunteerRow(env, volunteer) {
  const sheetId = env.GALA_VOLUNTEERS_SHEET_ID;
  if (!sheetId || !env.GOOGLE_SERVICE_ACCOUNT_JSON) return { skipped: true };

  const tab = tabFor(volunteer.event_slug);
  const token = await getAccessToken(env.GOOGLE_SERVICE_ACCOUNT_JSON);

  // Find the row whose column A == volunteer.id
  const findUrl = `${SHEETS_API}/${sheetId}/values/${encodeURIComponent(`${tab}!A:A`)}`;
  const findRes = await fetch(findUrl, { headers: { Authorization: `Bearer ${token}` } });
  if (!findRes.ok) throw new Error(`find ${findRes.status}: ${await findRes.text()}`);
  const findData = await findRes.json();
  const rows = findData.values || [];
  let rowNum = -1;
  for (let i = 0; i < rows.length; i++) {
    if (rows[i][0] === volunteer.id) { rowNum = i + 1; break; }
  }
  if (rowNum < 0) {
    // Not in sheet yet — append it instead.
    return appendVolunteerRow(env, volunteer);
  }

  const updateUrl = `${SHEETS_API}/${sheetId}/values/${encodeURIComponent(`${tab}!A${rowNum}:P${rowNum}`)}?valueInputOption=USER_ENTERED`;
  const updRes = await fetch(updateUrl, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ values: [rowFromVolunteer(volunteer)] }),
  });
  if (!updRes.ok) throw new Error(`update ${updRes.status}: ${await updRes.text()}`);
  return { ok: true, row: rowNum };
}

/**
 * Full backfill — wipe each tab and rewrite from D1. Use sparingly (admin only).
 */
export async function rebuildAllSheets(env, db) {
  const sheetId = env.GALA_VOLUNTEERS_SHEET_ID;
  if (!sheetId || !env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    return { skipped: true, reason: 'missing config' };
  }
  const token = await getAccessToken(env.GOOGLE_SERVICE_ACCOUNT_JSON);

  const events = await db.prepare(`SELECT slug FROM events WHERE active = 1`).all();
  const summary = {};

  for (const evt of events.results) {
    const tab = tabFor(evt.slug);
    const vols = await db.prepare(
      `SELECT * FROM volunteers WHERE event_slug = ? ORDER BY created_at ASC`
    ).bind(evt.slug).all();

    // Clear the tab below the header row (row 2 onwards)
    const clearUrl = `${SHEETS_API}/${sheetId}/values/${encodeURIComponent(`${tab}!A2:P10000`)}:clear`;
    await fetch(clearUrl, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });

    // Build all rows and write in one shot
    const rows = (vols.results || []).map(rowFromVolunteer);
    if (rows.length > 0) {
      const writeUrl = `${SHEETS_API}/${sheetId}/values/${encodeURIComponent(`${tab}!A2`)}?valueInputOption=USER_ENTERED`;
      const wRes = await fetch(writeUrl, {
        method: 'PUT',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ values: rows }),
      });
      if (!wRes.ok) throw new Error(`rebuild ${tab}: ${wRes.status} ${await wRes.text()}`);
    }
    summary[evt.slug] = rows.length;
  }
  return { ok: true, summary };
}

/**
 * Ensure each tab has the header row. Run once on first setup.
 */
export async function ensureHeaders(env) {
  const sheetId = env.GALA_VOLUNTEERS_SHEET_ID;
  if (!sheetId || !env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    return { skipped: true };
  }
  const token = await getAccessToken(env.GOOGLE_SERVICE_ACCOUNT_JSON);
  const results = {};
  for (const tab of Object.values(SLUG_TO_TAB)) {
    const url = `${SHEETS_API}/${sheetId}/values/${encodeURIComponent(`${tab}!A1:P1`)}?valueInputOption=USER_ENTERED`;
    const r = await fetch(url, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ values: [HEADER] }),
    });
    results[tab] = r.ok ? 'ok' : `${r.status}: ${await r.text()}`;
  }
  return results;
}

/* --------------------------- JWT → access token ------------------------- */

async function getAccessToken(saJsonStr) {
  // Accept either: (a) raw JSON string, (b) base64-encoded JSON
  let sa;
  if (typeof saJsonStr === 'object') {
    sa = saJsonStr;
  } else {
    let str = saJsonStr.trim();
    // Try plain JSON first; if that fails, try base64-decode.
    try {
      sa = JSON.parse(str);
    } catch {
      const decoded = atob(str);
      sa = JSON.parse(decoded);
    }
  }
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: TOKEN_URL,
    iat: now,
    exp: now + 3600,
  };
  const header = { alg: 'RS256', typ: 'JWT' };
  const enc = obj => b64url(new TextEncoder().encode(JSON.stringify(obj)));
  const unsigned = `${enc(header)}.${enc(claims)}`;
  const key = await importPrivateKey(sa.private_key);
  const sig = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' }, key, new TextEncoder().encode(unsigned)
  );
  const jwt = `${unsigned}.${b64url(new Uint8Array(sig))}`;

  const tRes = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });
  if (!tRes.ok) throw new Error(`token ${tRes.status}: ${await tRes.text()}`);
  return (await tRes.json()).access_token;
}

async function importPrivateKey(pem) {
  const clean = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s+/g, '');
  const der = Uint8Array.from(atob(clean), c => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'pkcs8',
    der.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  );
}

function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
