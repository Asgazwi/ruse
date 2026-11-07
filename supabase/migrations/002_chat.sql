-- ============================================================================
-- 002: plain-text chat (chat-only plan v4)
-- Changes from the old 002: can_message() also checks the SENDER (messaging_banned),
-- mark_read / register_push_token need an approved account, purge_old_messages() added.
-- UNTESTED on a real Postgres.
-- ============================================================================

create table public.blocks (
  blocker_id uuid not null references public.profiles (id) on delete cascade,
  blocked_id uuid not null references public.profiles (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id)
);

create table public.reports (
  id          uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references public.profiles (id) on delete cascade,
  reported_id uuid not null references public.profiles (id) on delete cascade,
  reason      text not null check (char_length(reason) between 1 and 500),
  status      text not null default 'open' check (status in ('open', 'resolved')),
  created_at  timestamptz not null default now()
);

create table public.messages (
  id           uuid primary key default gen_random_uuid(),
  sender_id    uuid not null references public.profiles (id) on delete cascade,
  recipient_id uuid not null references public.profiles (id) on delete cascade,
  body         text not null check (char_length(btrim(body)) between 1 and 500),
  created_at   timestamptz not null default now(),
  read_at      timestamptz,
  constraint messages_not_to_self check (sender_id <> recipient_id)
);
create index messages_pair_idx on public.messages (least(sender_id, recipient_id), greatest(sender_id, recipient_id), created_at desc);
create index messages_unread_idx on public.messages (recipient_id) where read_at is null;
create index messages_created_idx on public.messages (created_at);   -- for the 30-day purge

create table public.push_tokens (
  token      text primary key,
  user_id    uuid not null references public.profiles (id) on delete cascade,
  updated_at timestamptz not null default now()
);

-- May this person message that person?
-- sender: approved and not banned by an admin. recipient: approved and "messages on". Nobody blocked the other.
create function public.can_message(sender uuid, recipient uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles s where s.id = sender and s.allowed and not s.messaging_banned)
     and exists (select 1 from public.profiles r where r.id = recipient and r.allowed and not r.messaging_off)
     and not exists (select 1 from public.blocks b
                     where (b.blocker_id = recipient and b.blocked_id = sender)
                        or (b.blocker_id = sender    and b.blocked_id = recipient))
$$;

-- Same limits as the old backend: 5 per hour for accounts younger than 7 days, 40 per hour after that.
create function public.messages_rate_limit() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  is_new boolean;
  sent   int;
begin
  select added_at > now() - interval '7 days' into is_new from public.profiles where id = new.sender_id;
  select count(*) into sent from public.messages where sender_id = new.sender_id and created_at > now() - interval '1 hour';
  if sent >= (case when is_new then 5 else 40 end) then
    raise exception 'You have sent too many messages. Try again later.';
  end if;
  return new;
end $$;

create trigger messages_rate_limit_before_insert before insert on public.messages
for each row execute function public.messages_rate_limit();

alter table public.messages    enable row level security;
alter table public.blocks      enable row level security;
alter table public.reports     enable row level security;
alter table public.push_tokens enable row level security;

create policy messages_read on public.messages for select to authenticated
  using (public.is_member() and auth.uid() in (sender_id, recipient_id)
    and not exists (select 1 from public.blocks b where b.blocker_id = auth.uid()
      and b.blocked_id = case when sender_id = auth.uid() then recipient_id else sender_id end));

create policy messages_send on public.messages for insert to authenticated
  with check (public.is_member() and sender_id = auth.uid() and public.can_message(sender_id, recipient_id));

create policy messages_delete_own on public.messages for delete to authenticated
  using (sender_id = auth.uid());
-- No update policy on purpose: marking read goes through mark_read() below, so nobody can edit a message.

create policy blocks_own on public.blocks for all to authenticated
  using (blocker_id = auth.uid()) with check (blocker_id = auth.uid() and public.is_member());

create policy reports_send  on public.reports for insert to authenticated with check (reporter_id = auth.uid() and public.is_member());
create policy reports_admin on public.reports for select to authenticated using (public.is_admin());
create policy reports_close on public.reports for update to authenticated using (public.is_admin()) with check (public.is_admin());

-- Mark everything from one person as read.
create function public.mark_read(other uuid) returns void
language sql security definer set search_path = public as $$
  update public.messages set read_at = now()
  where recipient_id = auth.uid() and sender_id = other and read_at is null and public.is_member()
$$;

-- The inbox: one row per person, newest first, with the unread count and their picture.
create function public.inbox()
returns table (other_id uuid, username text, avatar_url text, last_body text, last_at timestamptz, last_from_me boolean, unread bigint)
language sql stable security definer set search_path = public as $$
  with mine as (
    select m.*, case when m.sender_id = auth.uid() then m.recipient_id else m.sender_id end as other_id
    from public.messages m
    where auth.uid() in (m.sender_id, m.recipient_id)
  ), last_one as (
    select distinct on (other_id) other_id, body, created_at, sender_id
    from mine order by other_id, created_at desc
  )
  select l.other_id, p.username, p.avatar_url, l.body, l.created_at, l.sender_id = auth.uid(),
         (select count(*) from mine x where x.other_id = l.other_id and x.recipient_id = auth.uid() and x.read_at is null)
  from last_one l
  join public.profiles p on p.id = l.other_id
  where public.is_member()
    and not exists (select 1 from public.blocks b where b.blocker_id = auth.uid() and b.blocked_id = l.other_id)
  order by l.created_at desc
$$;

-- A phone's notification address. A function, because a token may move between accounts on a shared phone.
create function public.register_push_token(t text) returns void
language sql security definer set search_path = public as $$
  insert into public.push_tokens (token, user_id)
  select t, auth.uid() where public.is_member()
  on conflict (token) do update set user_id = auth.uid(), updated_at = now()
$$;

create policy push_tokens_own on public.push_tokens for select to authenticated using (user_id = auth.uid());
create policy push_tokens_delete_own on public.push_tokens for delete to authenticated using (user_id = auth.uid());

-- Messages older than 30 days are deleted. Returns how many went.
-- Schedule it nightly (pg_cron: Dashboard > Integrations > Cron, or a scheduled Edge Function with the service role):
--   select public.purge_old_messages();
create function public.purge_old_messages() returns int
language plpgsql security definer set search_path = public as $$
declare removed int;
begin
  delete from public.messages where created_at < now() - interval '30 days';
  get diagnostics removed = row_count;
  return removed;
end $$;

-- Realtime: new and deleted messages reach the phone at once.
-- Note: Realtime does not apply RLS to DELETE events (every connected phone gets the deleted message id).
-- The id is a random uuid, so nothing leaks; it only costs traffic once the app is big.
alter publication supabase_realtime add table public.messages;
