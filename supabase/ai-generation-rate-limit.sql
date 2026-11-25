-- PusoAI server-side AI generation quotas
-- Run this file once in Supabase Dashboard > SQL Editor.
-- Limits are checked atomically inside PostgreSQL; browser values cannot raise them.

create table if not exists public.pusoai_ai_generation_quotas (
  quota_day date not null,
  bucket_type text not null check (bucket_type in ('global', 'ip', 'visitor')),
  bucket_hash text not null,
  generation_count integer not null default 0 check (generation_count >= 0),
  updated_at timestamptz not null default now(),
  primary key (quota_day, bucket_type, bucket_hash)
);

alter table public.pusoai_ai_generation_quotas enable row level security;

revoke all on table public.pusoai_ai_generation_quotas from public, anon, authenticated;
grant all on table public.pusoai_ai_generation_quotas to service_role;

create or replace function public.consume_pusoai_ai_generation(
  p_ip_hash text,
  p_visitor_hash text,
  p_ip_daily_limit integer default 20,
  p_visitor_daily_limit integer default 10,
  p_global_daily_limit integer default 100
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_today date := ((pg_catalog.now() at time zone 'Asia/Kolkata')::date);
  v_global_count integer;
  v_ip_count integer;
  v_visitor_count integer;
  v_reset_at timestamptz := ((v_today + 1)::timestamp at time zone 'Asia/Kolkata');
begin
  -- Only the server-side service-role client may consume quota.
  if coalesce(auth.role(), '') <> 'service_role' then
    raise exception 'Not authorized to consume PusoAI AI generation quota';
  end if;

  if p_ip_hash is null or p_ip_hash !~ '^[a-f0-9]{64}$'
     or p_visitor_hash is null or p_visitor_hash !~ '^[a-f0-9]{64}$' then
    raise exception 'Invalid quota identifier';
  end if;

  if p_ip_daily_limit < 1 or p_ip_daily_limit > 500
     or p_visitor_daily_limit < 1 or p_visitor_daily_limit > 500
     or p_global_daily_limit < 1 or p_global_daily_limit > 10000 then
    raise exception 'Invalid quota limit';
  end if;

  -- Serialize quota checks for the current day to prevent parallel requests
  -- from racing past the remaining allowance.
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext('pusoai_ai_generation'),
    pg_catalog.hashtext(v_today::text)
  );

  insert into public.pusoai_ai_generation_quotas
    (quota_day, bucket_type, bucket_hash, generation_count)
  values
    (v_today, 'global', 'global', 0),
    (v_today, 'ip', p_ip_hash, 0),
    (v_today, 'visitor', p_visitor_hash, 0)
  on conflict (quota_day, bucket_type, bucket_hash) do nothing;

  select generation_count into v_global_count
  from public.pusoai_ai_generation_quotas
  where quota_day = v_today and bucket_type = 'global' and bucket_hash = 'global';

  select generation_count into v_ip_count
  from public.pusoai_ai_generation_quotas
  where quota_day = v_today and bucket_type = 'ip' and bucket_hash = p_ip_hash;

  select generation_count into v_visitor_count
  from public.pusoai_ai_generation_quotas
  where quota_day = v_today and bucket_type = 'visitor' and bucket_hash = p_visitor_hash;

  if v_global_count >= p_global_daily_limit then
    return pg_catalog.jsonb_build_object(
      'allowed', false, 'scope', 'global', 'limit', p_global_daily_limit,
      'remaining', 0, 'reset_at', v_reset_at
    );
  end if;

  if v_ip_count >= p_ip_daily_limit then
    return pg_catalog.jsonb_build_object(
      'allowed', false, 'scope', 'ip', 'limit', p_ip_daily_limit,
      'remaining', 0, 'reset_at', v_reset_at
    );
  end if;

  if v_visitor_count >= p_visitor_daily_limit then
    return pg_catalog.jsonb_build_object(
      'allowed', false, 'scope', 'visitor', 'limit', p_visitor_daily_limit,
      'remaining', 0, 'reset_at', v_reset_at
    );
  end if;

  update public.pusoai_ai_generation_quotas
  set generation_count = generation_count + 1, updated_at = pg_catalog.now()
  where quota_day = v_today and bucket_type = 'global' and bucket_hash = 'global';

  update public.pusoai_ai_generation_quotas
  set generation_count = generation_count + 1, updated_at = pg_catalog.now()
  where quota_day = v_today and bucket_type = 'ip' and bucket_hash = p_ip_hash;

  update public.pusoai_ai_generation_quotas
  set generation_count = generation_count + 1, updated_at = pg_catalog.now()
  where quota_day = v_today and bucket_type = 'visitor' and bucket_hash = p_visitor_hash;

  return pg_catalog.jsonb_build_object(
    'allowed', true,
    'visitor_limit', p_visitor_daily_limit,
    'visitor_remaining', greatest(0, p_visitor_daily_limit - v_visitor_count - 1),
    'ip_limit', p_ip_daily_limit,
    'ip_remaining', greatest(0, p_ip_daily_limit - v_ip_count - 1),
    'global_limit', p_global_daily_limit,
    'global_remaining', greatest(0, p_global_daily_limit - v_global_count - 1),
    'reset_at', v_reset_at
  );
end;
$function$;

revoke all on function public.consume_pusoai_ai_generation(text, text, integer, integer, integer) from public, anon, authenticated;
grant execute on function public.consume_pusoai_ai_generation(text, text, integer, integer, integer) to service_role;
