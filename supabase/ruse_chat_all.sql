-- >>> supabase/migrations/001_profiles_and_access.sql
-- ============================================================================
-- 001: people and access (chat-only plan v4)
-- Changes from the old 001 (all from the 7 Nov review): messaging_banned (H2),
-- invited_users.added_at (M2), username_changed_at can no longer be set by hand,
-- handle_new_user falls back to "no username" instead of blocking sign-in (L1).
-- UNTESTED on a real Postgres. Run supabase/tests first.
-- ============================================================================

create type public.user_role   as enum ('reader', 'author', 'admin');
create type public.gender_kind as enum ('boy', 'girl', 'skip');

-- People who may use the app but have not signed in yet (added by an admin, or carried over from the old sheet).
create table public.invited_users (
  email               text primary key,
  role                public.user_role not null default 'reader',
  username            text,
  username_changed_at timestamptz,
  gender              public.gender_kind,
  avatar_url          text,
  messaging_off       boolean not null default false,
  added_at            timestamptz not null default now()
);

create table public.profiles (
  id                  uuid primary key references auth.users (id) on delete cascade,
  email               text not null unique,
  display_name        text not null default '',      -- the Google name: admins only, never shown to readers
  role                public.user_role not null default 'reader',
  allowed             boolean not null default false,
  request_status      text not null default 'pending' check (request_status in ('pending', 'rejected')),
  username            text,
  username_changed_at timestamptz,
  gender              public.gender_kind,
  avatar_url          text,
  messaging_off       boolean not null default false,   -- the person's own "do not disturb": stops RECEIVING
  messaging_banned    boolean not null default false,   -- admin only: stops SENDING
  role_request        text check (role_request is null or role_request = 'author'),
  added_at            timestamptz not null default now(),
  constraint username_shape check (
    username is null or (
      username ~ '^[A-Za-z0-9_.]{3,20}$'
      and username !~ '^[._]' and username !~ '[._]$' and username !~ '[._]{2,}'
      and lower(username) <> all (array[
        'admin','administrator','owner','mod','moderator','support','help','ruse','system','null',
        'undefined','everyone','all','me','you','reader','author','official','staff','root','test','guest'])
    )
  )
);
create unique index profiles_username_unique on public.profiles (lower(username)) where username is not null;

-- ---- who is asking? (used by every policy) ----
create function public.is_member() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select allowed from public.profiles where id = auth.uid()), false)
$$;

create function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select allowed and role = 'admin' from public.profiles where id = auth.uid()), false)
$$;

create function public.can_upload() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select allowed and role in ('author', 'admin') from public.profiles where id = auth.uid()), false)
$$;

-- ---- first sign-in: create the profile, using the invitation if there is one ----
-- If the invitation's username is already taken by a signed-in person, sign-in must still work:
-- the profile is made without a username and the person picks one on the profile screen.
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare invite public.invited_users%rowtype;
begin
  select * into invite from public.invited_users where lower(email) = lower(new.email);
  begin
    insert into public.profiles (id, email, display_name, role, allowed, username, username_changed_at, gender, avatar_url, messaging_off, added_at)
    values (
      new.id, lower(new.email), coalesce(new.raw_user_meta_data ->> 'full_name', ''),
      coalesce(invite.role, 'reader'), invite.email is not null,
      invite.username, invite.username_changed_at, invite.gender, invite.avatar_url,
      coalesce(invite.messaging_off, false), coalesce(invite.added_at, now())
    );
  exception when unique_violation then
    raise warning 'handle_new_user: username "%" is taken, creating % without a username', invite.username, new.email;
    insert into public.profiles (id, email, display_name, role, allowed, gender, avatar_url, messaging_off, added_at)
    values (
      new.id, lower(new.email), coalesce(new.raw_user_meta_data ->> 'full_name', ''),
      coalesce(invite.role, 'reader'), invite.email is not null,
      invite.gender, invite.avatar_url, coalesce(invite.messaging_off, false), coalesce(invite.added_at, now())
    );
  end;
  return new;
end $$;

create trigger on_auth_user_created after insert on auth.users
for each row execute function public.handle_new_user();

-- ---- what a normal person may NOT change on their own profile ----
create function public.profiles_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;              -- SQL editor, import script, Edge Functions
  if not public.is_admin() then
    if new.role is distinct from old.role or new.allowed is distinct from old.allowed
       or new.email is distinct from old.email or new.added_at is distinct from old.added_at
       or new.request_status is distinct from old.request_status
       or new.messaging_banned is distinct from old.messaging_banned then
      raise exception 'You cannot change that.';
    end if;
  end if;
  if new.username is distinct from old.username then
    if old.username is not null and old.username_changed_at > now() - interval '30 days' then
      raise exception 'You can change your username once every 30 days.';
    end if;
    new.username_changed_at := now();
  else
    new.username_changed_at := old.username_changed_at;       -- never set by hand (a null here used to skip the 30-day wait)
  end if;
  return new;
end $$;

create trigger profiles_guard_before_update before update on public.profiles
for each row execute function public.profiles_guard();

-- ---- Row Level Security ----
alter table public.profiles       enable row level security;
alter table public.invited_users  enable row level security;

create policy profiles_read_own     on public.profiles for select to authenticated using (id = auth.uid());
create policy profiles_read_admin   on public.profiles for select to authenticated using (public.is_admin());
create policy profiles_update_own   on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());
create policy profiles_update_admin on public.profiles for update to authenticated using (public.is_admin()) with check (public.is_admin());

create policy invited_admin_all on public.invited_users for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- What other readers may see about a person: username and picture, never the email.
-- (A view runs with its owner's rights on purpose, so readers see each other's public part only.
--  The Supabase Security Advisor will warn about this one view: that warning is expected.)
create view public.public_profiles as
  select id, username, avatar_url, role
  from public.profiles
  where allowed and username is not null and public.is_member();
grant select on public.public_profiles to authenticated;

-- >>> supabase/migrations/002_chat.sql
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

-- >>> supabase/migrations/003_guards_and_helpers.sql
-- ============================================================================
-- 003: guards and helpers for people and chat (chat-only plan v4)
--   1. username_available()      the app's checkUsername
--   2. invitations               one unique username among invitations
--   3. avatar links              only Google image hosts (CHECK THE OLD FORMAT FIRST, see below)
--   4. last admin guard          nobody can remove, demote or switch off the last allowed admin
--   5. who may call what
-- UNTESTED on a real Postgres.
-- ============================================================================

-- ---- 1. username_available ----
create function public.username_available(name text) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(
        name ~ '^[A-Za-z0-9_.]{3,20}$' and name !~ '^[._]' and name !~ '[._]$' and name !~ '[._]{2,}'
    and lower(name) <> all (array[
        'admin','administrator','owner','mod','moderator','support','help','ruse','system','null',
        'undefined','everyone','all','me','you','reader','author','official','staff','root','test','guest'])
    and not exists (select 1 from public.profiles p
                    where lower(p.username) = lower(name) and p.id is distinct from auth.uid())
    and not exists (select 1 from public.invited_users i
                    where lower(i.username) = lower(name)
                      and lower(i.email) is distinct from (select lower(email) from public.profiles where id = auth.uid())),
    false)
$$;

-- ---- 2. invitations may not hand out the same username twice ----
create unique index invited_users_username_unique on public.invited_users (lower(username)) where username is not null;

-- ---- 3. avatar links ----
-- The file service makes links like https://lh3.googleusercontent.com/d/<file id>.
-- BEFORE you push: look at what the OLD backend stored in avatar_url. If it is another host, add it to the list
-- (or the old rows will be refused when they are imported).
alter table public.profiles add constraint profiles_avatar_host_ok check (
  avatar_url is null or avatar_url ~ '^https://(lh[0-9]+\.googleusercontent\.com|drive\.google\.com|drive\.usercontent\.google\.com)/');
alter table public.invited_users add constraint invited_avatar_host_ok check (
  avatar_url is null or avatar_url ~ '^https://(lh[0-9]+\.googleusercontent\.com|drive\.google\.com|drive\.usercontent\.google\.com)/');

-- ---- 4. the last admin ----
-- Refuses to delete, demote or switch off an allowed admin when no other allowed admin would be left.
-- An advisory lock makes two admins removing each other at the same moment safe.
-- The SQL Editor and the service role (auth.uid() is null) are NOT blocked, so you can always repair by hand.
create function public.profiles_keep_one_admin() returns trigger
language plpgsql security definer set search_path = public as $$
declare others int;
begin
  if auth.uid() is null then
    if tg_op = 'DELETE' then return old; end if;
    return new;
  end if;
  if not (old.role = 'admin' and old.allowed) then
    if tg_op = 'DELETE' then return old; end if;
    return new;                                                -- old row was not an active admin: nothing to protect
  end if;
  if tg_op = 'UPDATE' and new.role = 'admin' and new.allowed then return new; end if;   -- still an active admin
  perform pg_advisory_xact_lock(7001);
  select count(*) into others from public.profiles where role = 'admin' and allowed and id <> old.id;
  if others = 0 then raise exception 'You cannot remove the last admin.'; end if;
  if tg_op = 'DELETE' then return old; end if;
  return new;
end $$;

create trigger profiles_keep_one_admin_row before update or delete on public.profiles
for each row execute function public.profiles_keep_one_admin();

-- ---- 5. who may call what ----
-- New functions are executable by everyone (public) and, on Supabase, by anon. Close them for the signed-out role.
-- Trigger functions never need EXECUTE to fire, so they are closed for everyone.
revoke execute on function public.is_member(), public.is_admin(), public.can_upload(),
  public.can_message(uuid, uuid), public.mark_read(uuid), public.inbox(), public.register_push_token(text),
  public.username_available(text)
  from public, anon;
grant execute on function public.is_member(), public.is_admin(), public.can_upload(),
  public.can_message(uuid, uuid), public.mark_read(uuid), public.inbox(), public.register_push_token(text),
  public.username_available(text)
  to authenticated;

revoke execute on function public.handle_new_user(), public.profiles_guard(), public.profiles_keep_one_admin(),
  public.messages_rate_limit(), public.purge_old_messages()
  from public, anon, authenticated;

