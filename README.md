# NetDefender

A polished, responsive SOC dashboard for real-time network intrusion monitoring, threat containment, firewall policy, incidents, sensors, and response playbooks.

## Run locally

```bash
npm install
npm run dev
```

With no Supabase configuration the app starts in a seeded, browser-local demo workspace. It generates a realistic live alert every 15 seconds and persists operator changes in local storage.

**Demo sign-in** (available after signing out of the auto-opened demo workspace):

- Email: `admin@netdefender.io`
- Password: `NetDefender!2026`

You can also sign out from the avatar menu and create a local viewer account. Local-mode passwords are SHA-256 hashed for the prototype; browser-local authentication is a demo fallback, not production identity management.

## Production Supabase setup

1. Create a Supabase project and enable Email/Password Auth. Set the production site URL and allowed redirect URLs; enable email confirmation if required by your policy.
2. Apply the schema (migrations create app tables, indexes, RLS policies, Realtime publication, structured playbook conditions, and an idempotent playbook execution ledger):

   ```bash
   supabase link --project-ref YOUR_PROJECT_REF
   supabase db push
   ```

   For local Supabase development, `supabase db reset` applies migrations and loads `supabase/seed.sql` automatically through `supabase/config.toml`.

3. Configure frontend values in `.env.local` (the anon key is public; **never** put the service-role key in Vite variables):

   ```env
   VITE_SUPABASE_URL=https://YOUR_PROJECT.supabase.co
   VITE_SUPABASE_ANON_KEY=YOUR_SUPABASE_ANON_KEY
   ```

4. Start the app with the Supabase variables configured, use `/login` to sign up, and confirm the address if email confirmation is enabled. The Auth trigger automatically creates `public.profiles` with the new user’s `viewer` role. Promote the first workspace admin in the trusted SQL editor, then (for a non-production project) load the demo fixtures:

   ```sql
   update public.profiles set role = 'admin' where email = 'admin@your-domain.example';
   ```

   ```bash
   psql "$SUPABASE_DB_URL" -f supabase/seed.sql
   ```

   The signup path never grants a role from user-supplied metadata. Analysts/admins can be assigned only by a trusted administrator.

5. Set server-only secrets and deploy Edge Functions:

   ```bash
   supabase secrets set \
     SUPABASE_SERVICE_ROLE_KEY=YOUR_SERVICE_ROLE_KEY \
     SIMULATOR_CRON_SECRET=LONG_RANDOM_SECRET \
     EXPIRE_BLOCKS_CRON_SECRET=ANOTHER_LONG_RANDOM_SECRET \
     FIREWALL_WEBHOOK_URL=https://your-firewall-control-plane.example/api/blocks \
     FIREWALL_WEBHOOK_TOKEN=YOUR_FIREWALL_TOKEN \
     RESEND_API_KEY=YOUR_RESEND_KEY \
     RESEND_FROM_EMAIL='NetDefender SOC <alerts@your-domain.example>' \
     SOC_NOTIFICATION_EMAIL=soc@your-domain.example \
     SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

   supabase functions deploy ingest-alert
   supabase functions deploy block-ip
   supabase functions deploy simulate-traffic
   supabase functions deploy send-notification
   supabase functions deploy evaluate-playbooks
   supabase functions deploy expire-blocks
   supabase functions deploy manage-api-keys
   ```

6. Configure a trusted scheduler (for example, GitHub Actions, a managed cron service, or an internal scheduler) to POST to `simulate-traffic` every 15 seconds for a demo environment, and to `expire-blocks` every minute. Include `x-cron-secret` with the matching server secret. **Do not enable simulated traffic in production.** The functions also validate the cron secret independently of the Supabase JWT gateway.

## Included routes

- `/` SOC dashboard with alert analytics, live source map, KPIs, and a realtime alert feed
- `/alerts` filtering, sorting, selection, investigation drawer, response actions, CSV export, and demo event generation
- `/blocked-ips` IP containment, expiration controls, JSON export, and unblock workflow
- `/firewall` rule CRUD, toggles, JSON import/export, and an audited kill switch
- `/incidents` drag-and-drop response kanban with timeline notes
- `/sensors` fleet telemetry and simulated restart controls
- `/playbooks` IF/THEN response automation builder
- `/reports` reporting filters, charts, CSV and PDF export
- `/audit` admin-only audit events
- `/settings` account, recovery, notification preferences, API key rotation, and theme
- `/docs` integration and deployment guide

Keyboard shortcuts: `⌘/Ctrl + K` opens the command palette; `G` then `D/A/B/S/P` jumps to Dashboard, Alerts, Blocked IPs, Sensors, or Playbooks.

## Backend layout

- `supabase/migrations/20261005000000_netdefender_schema.sql` — normalized schema, indexes, auth profile trigger, role guard, RLS, and realtime publication
- `supabase/seed.sql` — optional realistic SOC fixtures for a non-production workspace
- `supabase/functions/ingest-alert` — hashed API-key validation, validation, rate limit, and event ingest
- `supabase/functions/block-ip` — admin-authorized block/unblock plus optional firewall webhook
- `supabase/functions/simulate-traffic` — scheduler-only demo traffic generator
- `supabase/functions/send-notification` — in-app critical-alert notification plus Resend email and Slack dispatch for critical alerts and playbook actions
- `supabase/functions/evaluate-playbooks` — condition matching on new alerts, safe dry-run previews, idempotent per-alert runs, response actions, and audit recording
- `supabase/migrations/20261005010000_playbook_automation.sql` — structured conditions, `playbook_runs` ledger, and admin-only log access
- `supabase/functions/expire-blocks` — expiration cleanup and optional firewall unblocking
- `supabase/functions/manage-api-keys` — admin-only API key creation/revocation; only SHA-256 hashes are stored and the clear key is returned once

The frontend uses Supabase Auth, Postgres, RLS, Realtime, and Edge Functions when configured. In demo mode the same workflows use seeded Zustand state and local storage. Firewall integrations, email, and Slack require the corresponding server-side secrets and a compatible receiving service.

## Build

```bash
npm run build
```
