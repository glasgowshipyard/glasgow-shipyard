# glasgow-shipyard

glasgowshipyard.com: a static page (`public/`) on Cloudflare Pages (project `glasgow-shipyard`, deploys on
push to `main`, previews for other branches), plus one Pages Function for the contact form.

## Contact form

`public/index.html` posts to `/contact` (`functions/contact/index.ts`), which emails ops@glasgowshipyard.com
through Resend. It replaced Formspree (2026-11) because of spam. The checks are ported from craigzielinski.com's
newsletter signup (craig-zielinski repo, `SIGNUP-PROTECTION.md`), in `lib/guard.ts`:

1. **Origin** header must be the site's own origin
2. **Honeypot**: hidden `website` field must be empty
3. **Email format** (and name and message present)
4. **Signed form token** from `GET /contact/token` (the page is static, so it fetches one with JavaScript),
   valid 3 s to 24 h after it was issued
5. **Cloudflare Turnstile** (enforced only when both keys are set)
6. **Send limits** in D1: 3 per IP per hour, 3 per sender address per day, 15 per day in total. Resend's free
   plan allows 100 emails a day across the account, shared with the craigzielinski.com newsletter (capped at 40)
   and the Project MARTAC and Respec Training sign-in emails. Its 3 custom domains are taken (craigzielinski.com,
   noperator.com, respectraining.com), which is why the form sends from craigzielinski.com

Bots get the same "sent" answer as people, so they learn nothing. Messages arrive with the sender as reply-to.

### Setup (once)

| Item | Where |
|---|---|
| D1 database `glasgowshipyard` | Create it (dashboard: Storage & Databases → D1, or `npx wrangler d1 create glasgowshipyard`), put its id in `wrangler.toml`, then run `schema.sql` against it (D1 → the database → Console, or `npx wrangler d1 execute glasgowshipyard --remote --file=schema.sql`) |
| Turnstile widget | Dashboard → Turnstile → Add widget: Managed, pre-clearance off, hostnames `glasgowshipyard.com` and `glasgow-shipyard.pages.dev` (previews are subdomains of it). Put its site key in `wrangler.toml` (`TURNSTILE_SITE_KEY`) |
| Secrets | Workers & Pages → glasgow-shipyard → Settings → Variables and Secrets, for Production and Preview: `CONTACT_SECRET` (random string), `RESEND_API_KEY`, `TURNSTILE_SECRET_KEY` |
| After cutover | Disable the old Formspree form (`xqapznad`) so bots posting to it directly stop reaching ops@ |

`wrangler.toml` is the source of truth for the project's settings once deployed: those settings can be seen but
not edited in the dashboard. Secrets stay in the dashboard.

### Local test

```bash
npx wrangler d1 execute glasgowshipyard --local --file=schema.sql
```

```bash
npx wrangler pages dev --binding CONTACT_SECRET=test --binding RESEND_API_KEY=re_test --binding TURNSTILE_SITE_KEY=1x00000000000000000000AA --binding TURNSTILE_SECRET_KEY=1x0000000000000000000000000000000AA
```

The `1x…` keys are Cloudflare's always-pass Turnstile test keys. With a fake Resend key, a message that passes
every check ends in "Something went wrong" (Resend answers 401), which shows the whole path works.
