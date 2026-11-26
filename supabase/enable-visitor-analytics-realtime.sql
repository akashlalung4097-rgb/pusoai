-- PusoAI: enable secure Realtime updates for the owner-only Visitors & Traffic dashboard.
-- Run this once in Supabase Dashboard -> SQL Editor.
-- Visitor event rows remain unreadable to anonymous/public visitors.

begin;

alter table public.visitor_events enable row level security;

-- Realtime postgres_changes requires SELECT access to the changed rows.
-- Give that access only to authenticated sessions belonging to the site owner.
revoke select on table public.visitor_events from anon;
grant select on table public.visitor_events to authenticated;

do $policy$
begin
  if not exists (
    select 1
    from pg_policies
    where schemaname = 'public'
      and tablename = 'visitor_events'
      and policyname = 'PusoAI owner can read visitor analytics events'
  ) then
    create policy "PusoAI owner can read visitor analytics events"
      on public.visitor_events
      for select
      to authenticated
      using ((auth.jwt() ->> 'email') = 'pusoai001@gmail.com');
  end if;
end
$policy$;

-- Register the table in Supabase Realtime only if it is not already published.
do $publication$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (
       select 1
       from pg_publication_tables
       where pubname = 'supabase_realtime'
         and schemaname = 'public'
         and tablename = 'visitor_events'
     ) then
    alter publication supabase_realtime add table public.visitor_events;
  end if;
end
$publication$;

commit;

-- The dashboard also polls every 15 seconds while open as a fallback.
-- If the Realtime subscription cannot connect, refresh still works manually.
