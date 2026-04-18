# def-volunteers

Unified volunteer backend for the Davis Education Foundation Volunteer Hub.

**Live:** https://volunteers.daviskids.org
**D1:** `def-volunteers` (`2ac967ea-2f47-4265-808a-653a3f211005`)
**Cloudflare Account:** `77f3d6611f5ceab7651744268d434342`

## What this is

One Cloudflare Worker that serves as the backend for every DEF volunteer event —
Gala, ForeKids Golf Classic, Child Spree, and anything future. All volunteer
signups across all events land in one D1 database, differentiated by `event_slug`.

The frontend signup pages and admin UI live in `def-site`. This repo is backend only.

## Architecture

```
Signup pages (daviskids.org/volunteer/*)  ─┐
Childspree app (childspree.org)           ─┼─►  volunteers-api Worker  ─►  def-volunteers D1
Admin UI (daviskids.org/volunteer-admin)  ─┘          │
                                                       ├─►  Resend (confirmation emails, blasts)
                                                       └─►  Twilio (SMS blasts)
```

## Local dev

```bash
npm install -g wrangler
wrangler login
wrangler d1 execute def-volunteers --local --file=schema.sql
wrangler d1 execute def-volunteers --local --file=seed-events.sql
wrangler dev
```

## Deploy

```bash
wrangler deploy
```

Routes and D1 binding are wired in `wrangler.toml`.

## Secrets

These are set directly on the deployed Worker (never committed):

| Secret | Source |
|---|---|
| `SESSION_SECRET` | 32-byte random, HMAC for signed session cookies |
| `RESEND_API_KEY` | `re_...` from Resend dashboard |
| `TWILIO_ACCOUNT_SID` | Twilio console |
| `TWILIO_AUTH_TOKEN` | Twilio console |
| `TWILIO_FROM` | `+18019236121` (shared DEF number) |

Rotate via `wrangler secret put NAME`.

## Environment vars (in wrangler.toml)

| Var | Meaning |
|---|---|
| `ADMIN_EMAILS` | Comma-separated list of emails allowed to access admin endpoints |

## API

All routes under `https://volunteers.daviskids.org`.

### Public

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/api/health` | Liveness check |
| `GET`  | `/api/events` | List active events |
| `GET`  | `/api/events/:slug` | Single event detail |
| `GET`  | `/api/capacity/:slug` | Current counts per role/location/shift |
| `POST` | `/api/volunteers` | Submit a signup (body must include `event_slug`) |

### Admin (MSAL session cookie required)

| Method | Path | Purpose |
|---|---|---|
| `POST`   | `/api/auth/session` | Exchange MSAL `id_token` for session cookie |
| `POST`   | `/api/auth/logout` | Clear session |
| `GET`    | `/api/auth/role` | `admin` or `unknown` |
| `GET`    | `/api/admin/volunteers` | List with filters (`event`, `status`, `role`, `location`, `search`, `limit`) |
| `GET`    | `/api/admin/volunteers/:id` | Single |
| `PATCH`  | `/api/admin/volunteers/:id` | Update `status`, `role`, `location`, `shift`, `notes`, etc. |
| `DELETE` | `/api/admin/volunteers/:id` | Soft-cancel |
| `GET`    | `/api/admin/stats` | Aggregate counts |
| `GET`    | `/api/admin/person?email=` | Cross-event lookup for a single person |
| `POST`   | `/api/admin/events` | Create new event |
| `PATCH`  | `/api/admin/events/:slug` | Update event |
| `POST`   | `/api/admin/blast/email` | Send email blast (`subject`, `message`, optional `event`, `status` filters) |
| `POST`   | `/api/admin/blast/sms` | Send SMS blast (requires `sms_opt_in = 1`) |
| `GET`    | `/api/admin/export?event=` | CSV download |

Template variables in email/SMS bodies: `{{first_name}}`, `{{last_name}}`, `{{email}}`.

## Adding a new event

```sql
INSERT INTO events (slug, name, event_date, venue, accent_color, config)
VALUES ('spring-fling-2027', 'Spring Fling 2027', '2027-04-15', 'DEF Office',
        '#9333ea', '{"roles":["setup","host","cleanup"]}');
```

Then build a matching signup page at `daviskids.org/volunteer/{slug}` in the
`def-site` repo using the shared signup chassis.

## Data model

See `schema.sql`. The only rule that matters: **every volunteer record has an `event_slug`**.
Everything else is config.

---

Built by Skippy. For Scott. For Karah. For the kids.
