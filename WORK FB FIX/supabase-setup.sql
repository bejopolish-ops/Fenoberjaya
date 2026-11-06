-- Run in Supabase SQL Editor. Re-run after adding the boss viewer to create its
-- read-only RPC. Disable public sign-ups and create the admin from Authentication > Users.
create table if not exists public.workshop_state (
  user_id uuid primary key references auth.users (id) on delete cascade,
  state jsonb not null default
    '{"expenses":[],"goods":[],"shipments":[],"cashNotes":[],"employees":[],"attendance":[]}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.workshop_state enable row level security;

revoke all on table public.workshop_state from anon;
grant select, insert, update on table public.workshop_state to authenticated;

drop policy if exists "Admin reads own workshop data" on public.workshop_state;
create policy "Admin reads own workshop data"
  on public.workshop_state for select to authenticated
  using (auth.uid() = user_id);

drop policy if exists "Admin creates own workshop data" on public.workshop_state;
create policy "Admin creates own workshop data"
  on public.workshop_state for insert to authenticated
  with check (auth.uid() = user_id);

drop policy if exists "Admin updates own workshop data" on public.workshop_state;
create policy "Admin updates own workshop data"
  on public.workshop_state for update to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create or replace function public.get_boss_report(share_token text)
returns jsonb
language sql
stable
security definer
set search_path = pg_catalog, public
as $function$
  select jsonb_build_object(
    'expenses',
    coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'id', item.value -> 'id',
          'date', item.value -> 'date',
          'type', item.value -> 'type',
          'worker', item.value -> 'worker',
          'amount', item.value -> 'amount',
          'note', item.value -> 'note',
          'hasPhoto', coalesce(nullif(item.value ->> 'photo', '') is not null, false),
          'status', item.value -> 'status',
          'wageDetails', item.value -> 'wageDetails'
        ) order by item.value ->> 'date' desc
      )
      from jsonb_array_elements(coalesce(workshop.state -> 'expenses', '[]'::jsonb)) as item(value)
    ), '[]'::jsonb)
  )
  from public.workshop_state as workshop
  where length(share_token) = 64
    and workshop.state ->> 'reportShareToken' = share_token
  limit 1;
$function$;

revoke all on function public.get_boss_report(text) from public;
grant execute on function public.get_boss_report(text) to anon, authenticated;

create or replace function public.get_boss_expense_photo(share_token text, expense_id text)
returns text
language sql
stable
security definer
set search_path = pg_catalog, public
as $function$
  select item.value ->> 'photo'
  from public.workshop_state as workshop
  cross join lateral jsonb_array_elements(coalesce(workshop.state -> 'expenses', '[]'::jsonb)) as item(value)
  where length(share_token) = 64
    and workshop.state ->> 'reportShareToken' = share_token
    and item.value ->> 'id' = expense_id
    and coalesce(item.value ->> 'photo', '') <> ''
  limit 1;
$function$;

revoke all on function public.get_boss_expense_photo(text, text) from public;
grant execute on function public.get_boss_expense_photo(text, text) to anon, authenticated;