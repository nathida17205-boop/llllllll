-- setup.sql : วิทยาการคำนวณ ป.3 (21101) โรงเรียนบ้านหนองงูเห่า
-- รันทั้งไฟล์ครั้งเดียวใน Supabase SQL Editor

-- ========== 1) ตาราง ==========
create table public.teachers (
  user_id uuid primary key references auth.users(id) on delete cascade
);
create table public.students (
  id text primary key check (id ~ '^[0-9]{11}$'),          -- รหัสนักเรียน 11 หลัก
  title text, first_name text not null, last_name text not null, section text,
  user_id uuid unique references auth.users(id) on delete set null,   -- ว่าง = ยังไม่สมัคร
  photo_path text
);
create table public.attempts (
  id bigserial primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  kind text not null check (kind in ('pre','post')),
  score int not null check (score between 0 and 100),
  answers jsonb,
  created_at timestamptz not null default now(),
  unique (user_id, kind)                                    -- ทำได้ครั้งเดียวต่อชุด
);
create table public.progress (
  user_id uuid not null references auth.users(id) on delete cascade,
  unit int not null check (unit > 0), done boolean not null default false,
  primary key (user_id, unit)
);
create table public.submissions (
  id bigserial primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  unit int not null check (unit > 0),
  kind text not null check (kind in ('link','file')),
  url text check (url is null or url ~* '^https?://'),
  storage_path text, note text,
  score numeric check (score is null or score >= 0), teacher_comment text,
  created_at timestamptz not null default now(),
  check ((kind = 'link' and url is not null) or (kind = 'file' and storage_path is not null))
);
create table public.materials (
  id bigserial primary key,
  title text not null, kind text not null check (kind in ('file','link','video')),
  url text check (url is null or url ~* '^https?://'),
  storage_path text, file_name text,
  created_at timestamptz not null default now(),
  check ((kind = 'file' and storage_path is not null) or (kind in ('link','video') and url is not null))
);

-- ========== 2) ฟังก์ชัน ==========
create or replace function public.is_teacher() returns boolean
language sql stable security definer set search_path = public, pg_temp as $$
  select exists (select 1 from public.teachers where user_id = auth.uid());
$$;
revoke all on function public.is_teacher() from public, anon;
grant execute on function public.is_teacher() to authenticated;

-- ตรวจรหัสตอนสมัคร: อีเมลขึ้นต้นเลข 11 หลัก ต้องอยู่ในรายชื่อและยังไม่ถูกใช้ ไม่งั้นสมัครไม่ได้
-- อีเมลอื่น (ผู้สอน) ข้าม
create or replace function public.check_signup() returns trigger
language plpgsql security definer set search_path = public, pg_temp as $$
declare sid text := split_part(new.email, '@', 1);
begin
  if sid !~ '^[0-9]{11}$' then return new; end if;
  update public.students set user_id = new.id where id = sid and user_id is null;
  if not found then raise exception 'รหัสนักเรียนไม่อยู่ในรายชื่อ หรือถูกใช้สมัครแล้ว'; end if;
  return new;
end $$;
revoke all on function public.check_signup() from public, anon, authenticated;
create trigger trg_check_signup before insert on auth.users
  for each row execute function public.check_signup();

-- ========== 3) สิทธิ์ระดับตาราง/คอลัมน์ (ชั้นที่ 1) ==========
revoke all on all tables in schema public from anon;
revoke all on all tables in schema public from authenticated;
revoke all on all sequences in schema public from anon, authenticated;
grant usage on schema public to authenticated;

grant select on public.teachers, public.students, public.attempts, public.progress, public.submissions, public.materials to authenticated;
grant update (photo_path) on public.students to authenticated;               -- ผู้เรียนแก้ได้แค่รูป
grant insert, delete on public.attempts to authenticated;   -- delete: ผู้สอนใช้รีเซ็ตการทำแบบทดสอบ (จำกัดด้วยนโยบายด้านล่าง)
grant insert, update on public.progress to authenticated;
-- submissions: INSERT ได้เฉพาะคอลัมน์ที่ระบุ (ไม่มี score/teacher_comment) ; UPDATE ได้เฉพาะ score/teacher_comment
grant insert (user_id, unit, kind, url, storage_path, note) on public.submissions to authenticated;
grant update (score, teacher_comment) on public.submissions to authenticated;
grant insert, update, delete on public.materials to authenticated;
grant usage on sequence public.attempts_id_seq, public.submissions_id_seq, public.materials_id_seq to authenticated;

-- ========== 4) Row Level Security (ชั้นที่ 2) ==========
alter table public.teachers    enable row level security;
alter table public.students    enable row level security;
alter table public.attempts    enable row level security;
alter table public.progress    enable row level security;
alter table public.submissions enable row level security;
alter table public.materials   enable row level security;

create policy teachers_sel on public.teachers for select to authenticated using (user_id = auth.uid());

create policy students_sel on public.students for select to authenticated using (user_id = auth.uid() or public.is_teacher());
create policy students_upd on public.students for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy attempts_sel on public.attempts for select to authenticated using (user_id = auth.uid() or public.is_teacher());
create policy attempts_del on public.attempts for delete to authenticated using (public.is_teacher());
create policy attempts_ins on public.attempts for insert to authenticated with check (user_id = auth.uid());

create policy progress_sel on public.progress for select to authenticated using (user_id = auth.uid() or public.is_teacher());
create policy progress_ins on public.progress for insert to authenticated with check (user_id = auth.uid());
create policy progress_upd on public.progress for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy sub_sel on public.submissions for select to authenticated using (user_id = auth.uid() or public.is_teacher());
create policy sub_ins on public.submissions for insert to authenticated with check (user_id = auth.uid());
create policy sub_upd on public.submissions for update to authenticated using (public.is_teacher()) with check (public.is_teacher());
-- ผู้เรียนไม่มีนโยบาย UPDATE เลย + ไม่มีสิทธิ์คอลัมน์ score/teacher_comment ตอน INSERT => ให้คะแนนตัวเองไม่ได้

create policy mat_sel on public.materials for select to authenticated using (true);
create policy mat_ins on public.materials for insert to authenticated with check (public.is_teacher());
create policy mat_upd on public.materials for update to authenticated using (public.is_teacher()) with check (public.is_teacher());
create policy mat_del on public.materials for delete to authenticated using (public.is_teacher());

-- ========== 5) มุมมองสรุปผล (ใช้สิทธิ์ของผู้เรียกดู จึงถูก RLS กรอง) ==========
create view public.results with (security_invoker = true) as
select s.id, s.title, s.first_name, s.last_name, s.section, s.user_id,
       pre.score  as pre_score, post.score as post_score,
       coalesce((select count(*) from public.progress p where p.user_id = s.user_id and p.done), 0) as units_done,
       coalesce((select count(*) from public.submissions b where b.user_id = s.user_id), 0) as submissions_count,
       (select round(avg(b.score), 2) from public.submissions b where b.user_id = s.user_id and b.score is not null) as avg_submission_score
from public.students s
left join public.attempts pre  on pre.user_id  = s.user_id and pre.kind  = 'pre'
left join public.attempts post on post.user_id = s.user_id and post.kind = 'post';
revoke all on public.results from anon;
grant select on public.results to authenticated;

-- ========== 6) Storage (private) ==========
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types) values
 ('photos','photos',false, 2*1024*1024,  array['image/png','image/jpeg']),
 ('submissions','submissions',false, 20*1024*1024, array['image/png','image/jpeg','application/pdf','video/mp4']),
 ('materials','materials',false, 50*1024*1024, array[
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/pdf'])
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

-- photos & submissions: ผู้เรียนจัดการได้เฉพาะโฟลเดอร์ <uid>/ ผู้สอนอ่านได้
create policy photos_sel on storage.objects for select to authenticated
  using (bucket_id = 'photos' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_teacher()));
create policy photos_ins on storage.objects for insert to authenticated
  with check (bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text);
create policy photos_upd on storage.objects for update to authenticated
  using (bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text)
  with check (bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text);
create policy photos_del on storage.objects for delete to authenticated
  using (bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text);

create policy subs_sel on storage.objects for select to authenticated
  using (bucket_id = 'submissions' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_teacher()));
create policy subs_ins on storage.objects for insert to authenticated
  with check (bucket_id = 'submissions' and (storage.foldername(name))[1] = auth.uid()::text);
create policy subs_upd on storage.objects for update to authenticated
  using (bucket_id = 'submissions' and (storage.foldername(name))[1] = auth.uid()::text)
  with check (bucket_id = 'submissions' and (storage.foldername(name))[1] = auth.uid()::text);
create policy subs_del on storage.objects for delete to authenticated
  using (bucket_id = 'submissions' and (storage.foldername(name))[1] = auth.uid()::text);

-- materials: ทุกคนที่ล็อกอินอ่านได้ ผู้สอนเขียนได้
create policy mats_sel on storage.objects for select to authenticated using (bucket_id = 'materials');
create policy mats_ins on storage.objects for insert to authenticated with check (bucket_id = 'materials' and public.is_teacher());
create policy mats_upd on storage.objects for update to authenticated
  using (bucket_id = 'materials' and public.is_teacher()) with check (bucket_id = 'materials' and public.is_teacher());
create policy mats_del on storage.objects for delete to authenticated using (bucket_id = 'materials' and public.is_teacher());

-- ========== 7) รายชื่อผู้เรียน: ข้อมูลจำลอง 6 แถว ==========
-- นำเข้ารายชื่อจริง: ลบ 6 แถวนี้ที่ Table Editor > students แล้วกด Insert > Import data from CSV
-- หัวคอลัมน์ CSV: id,title,first_name,last_name,section  (ปล่อย user_id และ photo_path ว่าง)
insert into public.students (id, title, first_name, last_name, section) values
 ('10000000001','ด.ช.','ทดสอบ','หนึ่ง','1'), ('10000000002','ด.ญ.','ทดสอบ','สอง','1'),
 ('10000000003','ด.ช.','ทดสอบ','สาม','1'),  ('10000000004','ด.ญ.','ทดสอบ','สี่','2'),
 ('10000000005','ด.ช.','ทดสอบ','ห้า','2'),  ('10000000006','ด.ญ.','ทดสอบ','หก','2');

-- ========== 8) ตั้งผู้สอน ==========
-- ขั้นตอน: สร้างผู้ใช้ผู้สอนที่ Authentication > Users ก่อน แล้วแก้อีเมลด้านล่าง เอา /* และ */ ออก แล้วรันเฉพาะส่วนนี้
/*
insert into public.teachers (user_id)
select id from auth.users where email = 'ใส่อีเมลผู้สอนที่นี่';
*/
