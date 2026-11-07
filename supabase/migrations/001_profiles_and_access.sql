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
