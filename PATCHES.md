# Patches to def-volunteers/src/worker.js

Three surgical edits to worker.js. Each is small, reversible, and doesn't touch
any existing logic. The existing volunteer signup, admin, and email flows are
untouched.

## 1. Top of file — add import

Add this line at the top of worker.js with the other imports:

```js
import { appendVolunteerRow, updateVolunteerRow, rebuildAllSheets, ensureHeaders } from './sheets.js';
```

## 2. POST /api/volunteers — append after D1 insert (around line 383)

Right after the existing fire-and-forget email block, add another fire-and-forget
for the Sheets sync:

```js
  // Fire-and-forget Sheets append (don't block response)
  if (env.GALA_VOLUNTEERS_SHEET_ID) {
    const fullVol = await env.DB.prepare(
      `SELECT * FROM volunteers WHERE id = ?`
    ).bind(id).first();
    try { await appendVolunteerRow(env, fullVol); }
    catch (e) { console.error('sheets append failed', e); }
  }
```

## 3. PATCH /api/admin/volunteers/:id — update Sheet after D1 update

Find the admin update endpoint (search for `PATCH` and `volunteers`). Right
after the `UPDATE volunteers SET ...` succeeds, add:

```js
  if (env.GALA_VOLUNTEERS_SHEET_ID) {
    const fullVol = await env.DB.prepare(
      `SELECT * FROM volunteers WHERE id = ?`
    ).bind(volId).first();
    try { await updateVolunteerRow(env, fullVol); }
    catch (e) { console.error('sheets update failed', e); }
  }
```

## 4. New admin endpoints

```js
router.post('/api/admin/sheets/init', requireAdmin, async (req, env) => {
  const result = await ensureHeaders(env);
  return json(result);
});

router.post('/api/admin/sheets/rebuild', requireAdmin, async (req, env) => {
  const result = await rebuildAllSheets(env, env.DB);
  return json(result);
});
```

## 5. wrangler.toml — register secrets/vars

The two values are set as Worker secrets, not in wrangler.toml:

```bash
wrangler secret put GOOGLE_SERVICE_ACCOUNT_JSON   # paste full JSON
wrangler secret put GALA_VOLUNTEERS_SHEET_ID      # the workbook ID from URL
```

(Sheet ID could be a regular var instead of a secret since it's not sensitive,
but treating it as a secret keeps it out of git.)

## Operational flow after deploy

1. Run once: `POST /api/admin/sheets/init` → writes header rows to all 3 tabs
2. New signup arrives → row appears in Sheet within 2 sec
3. Sherry edits status in admin → Sheet row updates within 2 sec
4. If anything diverges: `POST /api/admin/sheets/rebuild` → wipe + rewrite from D1
