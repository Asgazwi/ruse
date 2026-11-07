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
