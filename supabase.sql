-- ============================================================
-- Chorus backend schema — run once in Supabase Dashboard → SQL Editor
-- Creates: profiles, servers, server_members, channels,
--          dm_conversations, dm_participants, friendships, messages
--          + RLS policies + auto-profile trigger + realtime
-- Safe to re-run (uses IF NOT EXISTS / DROP IF EXISTS).
-- ============================================================

create extension if not exists "pgcrypto";

-- ---------- profiles (1 row per auth user) ----------
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  username text unique not null,
  color text not null default '#3b82f6',
  status text not null default 'online',
  created_at timestamptz not null default now(),
  constraint username_len check (char_length(username) between 3 and 20),
  constraint username_chars check (username ~ '^[a-zA-Z0-9_]+$')
);

-- ---------- servers ----------
create table if not exists public.servers (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 32),
  owner_id uuid not null references public.profiles (id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.server_members (
  server_id uuid not null references public.servers (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (server_id, user_id)
);

create table if not exists public.channels (
  id uuid primary key default gen_random_uuid(),
  server_id uuid not null references public.servers (id) on delete cascade,
  name text not null check (char_length(name) between 1 and 24),
  kind text not null default 'text' check (kind in ('text', 'voice')),
  position int not null default 0,
  created_at timestamptz not null default now(),
  unique (server_id, name)
);

-- ---------- DMs ----------
create table if not exists public.dm_conversations (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now()
);

create table if not exists public.dm_participants (
  conversation_id uuid not null references public.dm_conversations (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  last_read_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);

-- ---------- friends ----------
create table if not exists public.friendships (
  id uuid primary key default gen_random_uuid(),
  requester_id uuid not null references public.profiles (id) on delete cascade,
  addressee_id uuid not null references public.profiles (id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'accepted', 'blocked')),
  created_at timestamptz not null default now(),
  unique (requester_id, addressee_id),
  check (requester_id <> addressee_id)
);

-- ---------- messages (server channel XOR dm conversation) ----------
create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  author_id uuid not null references public.profiles (id) on delete cascade,
  channel_id uuid references public.channels (id) on delete cascade,
  conversation_id uuid references public.dm_conversations (id) on delete cascade,
  body text not null check (char_length(body) between 1 and 2000),
  created_at timestamptz not null default now(),
  check (
    (channel_id is not null and conversation_id is null) or
    (channel_id is null and conversation_id is not null)
  )
);
create index if not exists messages_channel_idx on public.messages (channel_id, created_at);
create index if not exists messages_conversation_idx on public.messages (conversation_id, created_at);
create index if not exists channels_server_idx on public.channels (server_id, position);

-- ============================================================
-- Row Level Security
-- ============================================================
alter table public.profiles enable row level security;
alter table public.servers enable row level security;
alter table public.server_members enable row level security;
alter table public.channels enable row level security;
alter table public.dm_conversations enable row level security;
alter table public.dm_participants enable row level security;
alter table public.friendships enable row level security;
alter table public.messages enable row level security;

-- profiles: everyone logged in can read; owners write their own row
drop policy if exists "profiles readable" on public.profiles;
create policy "profiles readable" on public.profiles
  for select to authenticated using (true);
drop policy if exists "profiles insert own" on public.profiles;
create policy "profiles insert own" on public.profiles
  for insert to authenticated with check (auth.uid() = id);
drop policy if exists "profiles update own" on public.profiles;
create policy "profiles update own" on public.profiles
  for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);

-- servers: visible to owner + members; any user can create (as owner)
drop policy if exists "servers readable by members" on public.servers;
create policy "servers readable by members" on public.servers
  for select to authenticated using (
    auth.uid() = owner_id
    or exists (select 1 from public.server_members m
               where m.server_id = servers.id and m.user_id = auth.uid())
  );
drop policy if exists "servers creatable" on public.servers;
create policy "servers creatable" on public.servers
  for insert to authenticated with check (auth.uid() = owner_id);
drop policy if exists "servers owner manages" on public.servers;
create policy "servers owner manages" on public.servers
  for all to authenticated using (auth.uid() = owner_id) with check (auth.uid() = owner_id);

-- server_members: members see the roster; users join themselves, owners add/remove
drop policy if exists "members readable by members" on public.server_members;
create policy "members readable by members" on public.server_members
  for select to authenticated using (
    user_id = auth.uid()
    or exists (select 1 from public.server_members m2
               where m2.server_id = server_members.server_id and m2.user_id = auth.uid())
  );
drop policy if exists "members joinable" on public.server_members;
create policy "members joinable" on public.server_members
  for insert to authenticated with check (
    user_id = auth.uid()
    or exists (select 1 from public.servers s
               where s.id = server_members.server_id and s.owner_id = auth.uid())
  );
drop policy if exists "members leavable" on public.server_members;
create policy "members leavable" on public.server_members
  for delete to authenticated using (
    user_id = auth.uid()
    or exists (select 1 from public.servers s
               where s.id = server_members.server_id and s.owner_id = auth.uid())
  );

-- channels: readable/creatable by members; owner deletes/renames
drop policy if exists "channels readable by members" on public.channels;
create policy "channels readable by members" on public.channels
  for select to authenticated using (
    exists (select 1 from public.server_members m
            where m.server_id = channels.server_id and m.user_id = auth.uid())
  );
drop policy if exists "channels creatable by members" on public.channels;
create policy "channels creatable by members" on public.channels
  for insert to authenticated with check (
    exists (select 1 from public.server_members m
            where m.server_id = channels.server_id and m.user_id = auth.uid())
  );
drop policy if exists "channels owner manages" on public.channels;
create policy "channels owner manages" on public.channels
  for all to authenticated using (
    exists (select 1 from public.servers s
            where s.id = channels.server_id and s.owner_id = auth.uid())
  ) with check (
    exists (select 1 from public.servers s
            where s.id = channels.server_id and s.owner_id = auth.uid())
  );

-- dm_conversations: visible to participants; anyone logged in can start one
drop policy if exists "conversations visible to participants" on public.dm_conversations;
create policy "conversations visible to participants" on public.dm_conversations
  for select to authenticated using (
    exists (select 1 from public.dm_participants p
            where p.conversation_id = dm_conversations.id and p.user_id = auth.uid())
  );
drop policy if exists "conversations creatable" on public.dm_conversations;
create policy "conversations creatable" on public.dm_conversations
  for insert to authenticated with check (true);

-- dm_participants: participants see each other; inserts open (row only readable by participants)
drop policy if exists "participants visible to participants" on public.dm_participants;
create policy "participants visible to participants" on public.dm_participants
  for select to authenticated using (
    user_id = auth.uid()
    or exists (select 1 from public.dm_participants p2
               where p2.conversation_id = dm_participants.conversation_id and p2.user_id = auth.uid())
  );
drop policy if exists "participants addable" on public.dm_participants;
create policy "participants addable" on public.dm_participants
  for insert to authenticated with check (true);

-- friendships: only the two people involved see/touch the row
drop policy if exists "friendships visible to parties" on public.friendships;
create policy "friendships visible to parties" on public.friendships
  for select to authenticated using (
    auth.uid() = requester_id or auth.uid() = addressee_id
  );
drop policy if exists "friendships requestable" on public.friendships;
create policy "friendships requestable" on public.friendships
  for insert to authenticated with check (auth.uid() = requester_id);
drop policy if exists "friendships manageable by parties" on public.friendships;
create policy "friendships manageable by parties" on public.friendships
  for update to authenticated
  using (auth.uid() = requester_id or auth.uid() = addressee_id)
  with check (auth.uid() = requester_id or auth.uid() = addressee_id);
drop policy if exists "friendships removable by parties" on public.friendships;
create policy "friendships removable by parties" on public.friendships
  for delete to authenticated
  using (auth.uid() = requester_id or auth.uid() = addressee_id);

-- messages: read/send only inside your servers and DMs (no edit/delete in MVP)
drop policy if exists "messages readable in scope" on public.messages;
create policy "messages readable in scope" on public.messages
  for select to authenticated using (
    (channel_id is not null and exists (
      select 1 from public.channels c
      join public.server_members m on m.server_id = c.server_id
      where c.id = messages.channel_id and m.user_id = auth.uid()
    ))
    or
    (conversation_id is not null and exists (
      select 1 from public.dm_participants p
      where p.conversation_id = messages.conversation_id and p.user_id = auth.uid()
    ))
  );
drop policy if exists "messages sendable in scope" on public.messages;
create policy "messages sendable in scope" on public.messages
  for insert to authenticated with check (
    auth.uid() = author_id
    and (
      (channel_id is not null and exists (
        select 1 from public.channels c
        join public.server_members m on m.server_id = c.server_id
        where c.id = messages.channel_id and m.user_id = auth.uid()
      ))
      or
      (conversation_id is not null and exists (
        select 1 from public.dm_participants p
        where p.conversation_id = messages.conversation_id and p.user_id = auth.uid()
      ))
    )
  );

-- ============================================================
-- Auto-create profile on signup (username from metadata or email)
-- ============================================================
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
declare
  base text;
  uname text;
  i int;
begin
  base := coalesce(nullif(new.raw_user_meta_data ->> 'username', ''), split_part(new.email, '@', 1));
  base := regexp_replace(base, '[^a-zA-Z0-9_]', '_', 'g');
  base := substring(base from 1 for 20);
  if base is null or char_length(base) < 3 then
    base := (coalesce(base, '') || '_user');
  end if;
  base := substring(base from 1 for 20);
  uname := base;
  for i in 1..100 loop
    begin
      insert into public.profiles (id, username) values (new.id, uname);
      exit;
    exception when unique_violation then
      uname := substring(base from 1 for 15) || '_' || floor(random() * 10000)::text;
    end;
  end loop;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ============================================================
-- Realtime: live new-message events on public.messages
-- (also enableable via Dashboard → Database → Replication)
-- ============================================================
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'messages'
  ) then
    alter publication supabase_realtime add table public.messages;
  end if;
end
$$;
