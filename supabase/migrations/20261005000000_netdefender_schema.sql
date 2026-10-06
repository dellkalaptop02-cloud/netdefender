-- NetDefender SOC schema · PostgreSQL / Supabase
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  full_name text not null default '',
  role text not null default 'viewer' check (role in ('admin','analyst','viewer')),
  avatar_url text,
  created_at timestamptz not null default now()
);

create or replace function public.get_my_role()
returns text language sql stable security definer set search_path = public
as $$
  select coalesce((select role from public.profiles where id = auth.uid()), 'viewer')
$$;
revoke all on function public.get_my_role() from public;
grant execute on function public.get_my_role() to authenticated;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id, email, full_name, role)
  values (new.id, coalesce(new.email, ''), coalesce(new.raw_user_meta_data ->> 'full_name', ''), 'viewer')
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;
drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.prevent_profile_role_escalation()
returns trigger language plpgsql security definer set search_path = public
as $$
begin
  if auth.uid() = old.id and public.get_my_role() <> 'admin' and new.role <> old.role then
    raise exception 'Only a workspace admin can change a profile role';
  end if;
  return new;
end;
$$;
drop trigger if exists prevent_profile_role_change on public.profiles;
create trigger prevent_profile_role_change before update on public.profiles
for each row execute procedure public.prevent_profile_role_escalation();

create table if not exists public.alerts (
  id text primary key,
  "timestamp" timestamptz not null default now(),
  severity text not null check (severity in ('low','medium','high','critical')),
  source_ip text not null,
  source_country text,
  source_lat double precision,
  source_lng double precision,
  destination_ip text,
  protocol text not null default 'TCP',
  attack_type text not null,
  signature text not null default '',
  status text not null default 'new' check (status in ('new','investigating','resolved','blocked')),
  raw_log text not null default '',
  created_at timestamptz not null default now()
);
create index if not exists alerts_timestamp_idx on public.alerts ("timestamp" desc);
create index if not exists alerts_severity_status_idx on public.alerts (severity, status);
create index if not exists alerts_source_ip_idx on public.alerts (source_ip);

create table if not exists public.blocked_ips (
  id text primary key,
  ip text not null,
  reason text not null,
  blocked_by text,
  blocked_at timestamptz not null default now(),
  expires_at timestamptz,
  is_active boolean not null default true
);
create unique index if not exists blocked_ips_active_ip_idx on public.blocked_ips (ip) where is_active = true;
create index if not exists blocked_ips_expiry_idx on public.blocked_ips (expires_at) where is_active = true;

create table if not exists public.firewall_rules (
  id text primary key,
  name text not null,
  action text not null check (action in ('allow','deny')),
  protocol text not null default 'ANY',
  source text not null default 'ANY',
  destination text not null default 'ANY',
  port text not null default 'ANY',
  enabled boolean not null default true,
  created_by text,
  created_at timestamptz not null default now()
);

create table if not exists public.incidents (
  id text primary key,
  title text not null,
  description text not null default '',
  severity text not null default 'medium' check (severity in ('low','medium','high','critical')),
  status text not null default 'new' check (status in ('new','investigating','resolved')),
  assigned_to text not null default 'Unassigned',
  created_at timestamptz not null default now(),
  resolved_at timestamptz,
  notes jsonb not null default '[]'::jsonb
);
create index if not exists incidents_status_idx on public.incidents (status, created_at desc);

create table if not exists public.sensors (
  id text primary key,
  name text not null,
  type text not null check (type in ('Suricata','Zeek','Wazuh')),
  ip text not null,
  status text not null default 'online' check (status in ('online','offline','warning')),
  cpu integer not null default 0 check (cpu between 0 and 100),
  memory integer not null default 0 check (memory between 0 and 100),
  uptime text not null default '—',
  last_heartbeat timestamptz not null default now()
);

create table if not exists public.audit_logs (
  id text primary key,
  user_id uuid references public.profiles(id) on delete set null,
  action text not null,
  target text not null default '',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists audit_logs_created_at_idx on public.audit_logs (created_at desc);

create table if not exists public.notifications (
  id text primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  message text not null,
  type text not null default 'info' check (type in ('critical','warning','success','info')),
  read boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists notifications_user_read_idx on public.notifications (user_id, read, created_at desc);

create table if not exists public.playbooks (
  id text primary key,
  name text not null,
  trigger_condition text not null,
  actions_json jsonb not null default '[]'::jsonb,
  enabled boolean not null default true,
  created_at timestamptz not null default now()
);

-- API keys are never readable by browser clients. Store SHA-256 hashes only.
create table if not exists public.api_keys (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  key_hash text not null unique,
  key_prefix text not null,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz
);
create index if not exists api_keys_hash_active_idx on public.api_keys (key_hash) where revoked_at is null;

create table if not exists public.api_key_rate_limits (
  key_id uuid not null references public.api_keys(id) on delete cascade,
  window_start timestamptz not null,
  request_count integer not null default 0,
  primary key (key_id, window_start)
);
alter table public.api_key_rate_limits enable row level security;
create policy "api_key_rate_limits_no_client_access" on public.api_key_rate_limits for all to authenticated using (false) with check (false);
create or replace function public.consume_api_key_rate_limit(p_key_id uuid, p_limit integer default 120, p_window_seconds integer default 60)
returns boolean language plpgsql security definer set search_path = public
as $$
declare
  bucket timestamptz := to_timestamp(floor(extract(epoch from clock_timestamp()) / greatest(p_window_seconds, 1)) * greatest(p_window_seconds, 1));
  current_count integer;
begin
  insert into public.api_key_rate_limits (key_id, window_start, request_count) values (p_key_id, bucket, 1)
  on conflict (key_id, window_start) do update set request_count = api_key_rate_limits.request_count + 1
  returning request_count into current_count;
  return current_count <= greatest(p_limit, 1);
end;
$$;
revoke all on function public.consume_api_key_rate_limit(uuid, integer, integer) from public, anon, authenticated;
grant execute on function public.consume_api_key_rate_limit(uuid, integer, integer) to service_role;

-- Explicitly enable RLS on every application table.
alter table public.profiles enable row level security;
alter table public.alerts enable row level security;
alter table public.blocked_ips enable row level security;
alter table public.firewall_rules enable row level security;
alter table public.incidents enable row level security;
alter table public.sensors enable row level security;
alter table public.audit_logs enable row level security;
alter table public.notifications enable row level security;
alter table public.playbooks enable row level security;
alter table public.api_keys enable row level security;

-- Profiles: users can read their own profile; admins can manage all profiles.
drop policy if exists "profiles_select_self_or_admin" on public.profiles;
create policy "profiles_select_self_or_admin" on public.profiles for select to authenticated
using (id = auth.uid() or public.get_my_role() = 'admin');
drop policy if exists "profiles_update_self_or_admin" on public.profiles;
create policy "profiles_update_self_or_admin" on public.profiles for update to authenticated
using (id = auth.uid() or public.get_my_role() = 'admin') with check (id = auth.uid() or public.get_my_role() = 'admin');
drop policy if exists "profiles_admin_insert" on public.profiles;
create policy "profiles_admin_insert" on public.profiles for insert to authenticated
with check (public.get_my_role() = 'admin');
drop policy if exists "profiles_admin_delete" on public.profiles;
create policy "profiles_admin_delete" on public.profiles for delete to authenticated
using (public.get_my_role() = 'admin');

-- All signed-in roles can view detections. Analysts can update workflow/severity; admins have full access.
drop policy if exists "alerts_select_authenticated" on public.alerts;
create policy "alerts_select_authenticated" on public.alerts for select to authenticated using (auth.uid() is not null);
drop policy if exists "alerts_analyst_update" on public.alerts;
create policy "alerts_analyst_update" on public.alerts for update to authenticated
using (public.get_my_role() in ('analyst','admin')) with check (public.get_my_role() in ('analyst','admin'));
drop policy if exists "alerts_admin_insert" on public.alerts;
create policy "alerts_admin_insert" on public.alerts for insert to authenticated with check (public.get_my_role() = 'admin');
drop policy if exists "alerts_admin_delete" on public.alerts;
create policy "alerts_admin_delete" on public.alerts for delete to authenticated using (public.get_my_role() = 'admin');

-- Configuration tables are read-only to analysts/viewers and writable by admins.
drop policy if exists "blocked_ips_select_authenticated" on public.blocked_ips;
create policy "blocked_ips_select_authenticated" on public.blocked_ips for select to authenticated using (auth.uid() is not null);
drop policy if exists "blocked_ips_admin_all" on public.blocked_ips;
create policy "blocked_ips_admin_all" on public.blocked_ips for all to authenticated using (public.get_my_role() = 'admin') with check (public.get_my_role() = 'admin');

drop policy if exists "firewall_rules_select_authenticated" on public.firewall_rules;
create policy "firewall_rules_select_authenticated" on public.firewall_rules for select to authenticated using (auth.uid() is not null);
drop policy if exists "firewall_rules_admin_all" on public.firewall_rules;
create policy "firewall_rules_admin_all" on public.firewall_rules for all to authenticated using (public.get_my_role() = 'admin') with check (public.get_my_role() = 'admin');

drop policy if exists "sensors_select_authenticated" on public.sensors;
create policy "sensors_select_authenticated" on public.sensors for select to authenticated using (auth.uid() is not null);
drop policy if exists "sensors_admin_all" on public.sensors;
create policy "sensors_admin_all" on public.sensors for all to authenticated using (public.get_my_role() = 'admin') with check (public.get_my_role() = 'admin');

drop policy if exists "playbooks_select_authenticated" on public.playbooks;
create policy "playbooks_select_authenticated" on public.playbooks for select to authenticated using (auth.uid() is not null);
drop policy if exists "playbooks_admin_all" on public.playbooks;
create policy "playbooks_admin_all" on public.playbooks for all to authenticated using (public.get_my_role() = 'admin') with check (public.get_my_role() = 'admin');

-- Incident workflow: analyst update rights, admin full CRUD.
drop policy if exists "incidents_select_authenticated" on public.incidents;
create policy "incidents_select_authenticated" on public.incidents for select to authenticated using (auth.uid() is not null);
drop policy if exists "incidents_analyst_update" on public.incidents;
create policy "incidents_analyst_update" on public.incidents for update to authenticated
using (public.get_my_role() in ('analyst','admin')) with check (public.get_my_role() in ('analyst','admin'));
drop policy if exists "incidents_admin_all" on public.incidents;
create policy "incidents_admin_all" on public.incidents for all to authenticated using (public.get_my_role() = 'admin') with check (public.get_my_role() = 'admin');

-- Audit rows can be inserted by the actor, read by admins only, never updated/deleted from clients.
drop policy if exists "audit_admin_read" on public.audit_logs;
create policy "audit_admin_read" on public.audit_logs for select to authenticated using (public.get_my_role() = 'admin');
drop policy if exists "audit_actor_insert" on public.audit_logs;
create policy "audit_actor_insert" on public.audit_logs for insert to authenticated with check (user_id = auth.uid() or public.get_my_role() = 'admin');

-- Notifications are private to the recipient; administrators can inspect workspace notifications.
drop policy if exists "notifications_read_own_or_admin" on public.notifications;
create policy "notifications_read_own_or_admin" on public.notifications for select to authenticated
using (user_id = auth.uid() or public.get_my_role() = 'admin');
drop policy if exists "notifications_update_own_or_admin" on public.notifications;
create policy "notifications_update_own_or_admin" on public.notifications for update to authenticated
using (user_id = auth.uid() or public.get_my_role() = 'admin') with check (user_id = auth.uid() or public.get_my_role() = 'admin');
drop policy if exists "notifications_admin_insert" on public.notifications;
create policy "notifications_admin_insert" on public.notifications for insert to authenticated with check (public.get_my_role() = 'admin');
drop policy if exists "notifications_admin_delete" on public.notifications;
create policy "notifications_admin_delete" on public.notifications for delete to authenticated using (public.get_my_role() = 'admin');

-- API-key hashes are only queried through service-role Edge Functions.
drop policy if exists "api_keys_no_client_access" on public.api_keys;
create policy "api_keys_no_client_access" on public.api_keys for all to authenticated using (false) with check (false);

-- Realtime publication for live detections, containment, and sensor state.
do $$ begin
  alter publication supabase_realtime add table public.alerts;
exception when duplicate_object then null; when undefined_object then null; end $$;
do $$ begin
  alter publication supabase_realtime add table public.blocked_ips;
exception when duplicate_object then null; when undefined_object then null; end $$;
do $$ begin
  alter publication supabase_realtime add table public.sensors;
exception when duplicate_object then null; when undefined_object then null; end $$;
do $$ begin
  alter publication supabase_realtime add table public.notifications;
exception when duplicate_object then null; when undefined_object then null; end $$;

-- Strip default/public grants, then grant only the table operations that RLS policies govern.
-- In particular, browser clients receive no access to API-key hashes or rate-limit buckets.
grant usage on schema public to authenticated, service_role;
revoke all on public.profiles, public.alerts, public.blocked_ips, public.firewall_rules, public.incidents, public.sensors, public.audit_logs, public.notifications, public.playbooks, public.api_keys, public.api_key_rate_limits from anon, authenticated;

grant select, update, insert, delete on public.profiles to authenticated;
grant select, insert, update, delete on public.alerts, public.blocked_ips, public.firewall_rules, public.incidents, public.sensors, public.playbooks to authenticated;
grant select, insert on public.audit_logs to authenticated;
grant select on public.notifications to authenticated;
grant update (read) on public.notifications to authenticated;

grant all on public.profiles, public.alerts, public.blocked_ips, public.firewall_rules, public.incidents, public.sensors, public.audit_logs, public.notifications, public.playbooks, public.api_keys, public.api_key_rate_limits to service_role;
