-- Structured playbook criteria plus an auditable, idempotent execution ledger.
alter table public.playbooks
  add column if not exists condition_json jsonb;

do $$
declare
  playbook_row record;
  parts text[];
begin
  for playbook_row in
    select id, trigger_condition
    from public.playbooks
    where condition_json is null
  loop
    parts := regexp_match(
      playbook_row.trigger_condition,
      '^(severity|attack_type|source_country|protocol)\s*(=|contains|>)\s*(.+)$',
      'i'
    );
    if parts is null then
      -- An unknown legacy expression is intentionally made non-matching rather than
      -- silently broadening an automation rule during migration.
      update public.playbooks
      set condition_json = '{"field":"severity","operator":"equals","value":"__legacy_unparsed__"}'::jsonb
      where id = playbook_row.id;
    else
      update public.playbooks
      set condition_json = jsonb_build_object(
        'field', lower(parts[1]),
        'operator', case parts[2] when '>' then 'greater_than' when '=' then 'equals' else 'contains' end,
        'value', btrim(parts[3])
      )
      where id = playbook_row.id;
    end if;
  end loop;
end;
$$;

alter table public.playbooks
  alter column condition_json set default '{"field":"severity","operator":"equals","value":"__unconfigured__"}'::jsonb,
  alter column condition_json set not null;

create table if not exists public.playbook_runs (
  id text primary key,
  playbook_id text not null references public.playbooks(id) on delete cascade,
  alert_id text not null references public.alerts(id) on delete cascade,
  status text not null default 'running' check (status in ('running','succeeded','failed')),
  condition_json jsonb not null default '{}'::jsonb,
  actions_json jsonb not null default '[]'::jsonb,
  result_json jsonb not null default '{}'::jsonb,
  error_message text,
  started_at timestamptz not null default now(),
  completed_at timestamptz,
  unique (playbook_id, alert_id)
);
create index if not exists playbook_runs_started_idx on public.playbook_runs (started_at desc);
create index if not exists playbook_runs_status_idx on public.playbook_runs (status, started_at desc);

alter table public.playbook_runs enable row level security;
drop policy if exists "playbook_runs_admin_read" on public.playbook_runs;
create policy "playbook_runs_admin_read" on public.playbook_runs
  for select to authenticated using (public.get_my_role() = 'admin');

revoke all on public.playbook_runs from anon, authenticated;
grant select on public.playbook_runs to authenticated;
grant all on public.playbook_runs to service_role;

-- Automated incident creation should appear in the open SOC workspace without a reload.
do $$ begin
  alter publication supabase_realtime add table public.incidents;
exception when duplicate_object then null; when undefined_object then null; end $$;
do $$ begin
  alter publication supabase_realtime add table public.playbook_runs;
exception when duplicate_object then null; when undefined_object then null; end $$;
