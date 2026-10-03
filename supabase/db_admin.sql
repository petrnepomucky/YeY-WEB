-- =====================================================================
-- YeY – správa databáze (dbadmin.html)
-- Serverové funkce pro administrátorské rozhraní. Nasazeno v projektech
-- "Stavební materiál" (fvrpuddkarujfttoaavb) a "YeY - Online Office"
-- (hkzhjoveiqadezmvksdz).
--
-- Všechny funkce jsou SECURITY DEFINER a začínají kontrolou admin klíče
-- (bcrypt hash v tabulce db_admin_klic). Tabulka nemá žádné RLS politiky,
-- takže se k ní přes API nikdo nedostane.
--
-- Změna klíče:
--   update public.db_admin_klic set hash = extensions.crypt('NOVY-KLIC', extensions.gen_salt('bf'));
-- =====================================================================

create table if not exists public.db_admin_klic (
  id   int primary key generated always as identity,
  hash text not null
);
alter table public.db_admin_klic enable row level security;
revoke all on public.db_admin_klic from anon, authenticated;
comment on table public.db_admin_klic is 'Hash admin klíče pro správu databáze (dbadmin.html). Bez RLS politik = nepřístupné přes API.';

-- ---------- kontrola klíče ----------
create or replace function public.db_admin_ok(p_klic text)
returns void language plpgsql security definer
set search_path = public, extensions, pg_catalog as $$
begin
  if not exists (select 1 from db_admin_klic where hash = crypt(coalesce(p_klic,''), hash)) then
    perform pg_sleep(0.5);
    raise exception 'Neplatný admin klíč' using errcode = '28000';
  end if;
end $$;

-- ---------- ověření názvu tabulky (jen schéma public) ----------
create or replace function public.db_admin_tab(p_tabulka text)
returns regclass language plpgsql stable security definer
set search_path = public, pg_catalog as $$
declare t regclass;
begin
  select c.oid::regclass into t
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'public' and c.relname = p_tabulka and c.relkind in ('r','p','v','m','f');
  if t is null then raise exception 'Tabulka „%“ neexistuje', p_tabulka; end if;
  return t;
end $$;

-- ---------- primární klíč ----------
create or replace function public.db_admin_pk(t regclass)
returns text[] language sql stable security definer
set search_path = public, pg_catalog as $$
  select coalesce(array_agg(a.attname::text order by k.ord), '{}')
    from pg_index i
    cross join lateral unnest(i.indkey) with ordinality k(attnum, ord)
    join pg_attribute a on a.attrelid = i.indrelid and a.attnum = k.attnum
   where i.indrelid = t and i.indisprimary
$$;

-- ---------- přehled databáze a tabulek ----------
create or replace function public.db_admin_info(p_klic text)
returns jsonb language plpgsql security definer
set search_path = public, pg_catalog as $$
begin
  perform db_admin_ok(p_klic);
  return jsonb_build_object(
    'db', current_database(),
    'verze', split_part(version(), ' ', 2),
    'velikost', pg_database_size(current_database()),
    'cas', now(),
    'tabulky', (
      select coalesce(jsonb_agg(jsonb_build_object(
          'nazev', c.relname,
          'typ', case c.relkind when 'r' then 'tabulka' when 'p' then 'tabulka' when 'v' then 'pohled'
                                when 'm' then 'mat. pohled' else 'cizí' end,
          'radku', greatest(coalesce(s.n_live_tup, c.reltuples::bigint), 0),
          'velikost', pg_total_relation_size(c.oid),
          'rls', c.relrowsecurity,
          'politik', (select count(*) from pg_policy p where p.polrelid = c.oid),
          'komentar', obj_description(c.oid, 'pg_class'),
          'pk', db_admin_pk(c.oid::regclass)
        ) order by c.relname), '[]')
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      left join pg_stat_user_tables s on s.relid = c.oid
     where n.nspname = 'public' and c.relkind in ('r','p','v','m','f')
       and not c.relispartition and c.relname <> 'db_admin_klic')
  );
end $$;

-- ---------- struktura tabulky ----------
create or replace function public.db_admin_struktura(p_klic text, p_tabulka text)
returns jsonb language plpgsql security definer
set search_path = public, pg_catalog as $$
declare t regclass;
begin
  perform db_admin_ok(p_klic);
  t := db_admin_tab(p_tabulka);
  return jsonb_build_object(
    'nazev', p_tabulka,
    'pk', db_admin_pk(t),
    'upravitelna', (select relkind in ('r','p') from pg_class where oid = t),
    'komentar', obj_description(t, 'pg_class'),
    'sloupce', (
      select coalesce(jsonb_agg(jsonb_build_object(
          'nazev', a.attname,
          'typ', format_type(a.atttypid, a.atttypmod),
          'zakl', t2.typcategory,
          'nullable', not a.attnotnull,
          'default', pg_get_expr(d.adbin, d.adrelid),
          'identity', a.attidentity <> '',
          'generovany', a.attgenerated <> '',
          'komentar', col_description(t, a.attnum)
        ) order by a.attnum), '[]')
      from pg_attribute a
      join pg_type t2 on t2.oid = a.atttypid
      left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum
     where a.attrelid = t and a.attnum > 0 and not a.attisdropped),
    'indexy', (
      select coalesce(jsonb_agg(jsonb_build_object(
          'nazev', ic.relname, 'definice', pg_get_indexdef(i.indexrelid),
          'velikost', pg_relation_size(i.indexrelid),
          'pouziti', coalesce(st.idx_scan, 0)) order by ic.relname), '[]')
      from pg_index i
      join pg_class ic on ic.oid = i.indexrelid
      left join pg_stat_user_indexes st on st.indexrelid = i.indexrelid
     where i.indrelid = t),
    'politiky', (
      select coalesce(jsonb_agg(jsonb_build_object(
          'nazev', p.polname,
          'prikaz', case p.polcmd when 'r' then 'SELECT' when 'a' then 'INSERT' when 'w' then 'UPDATE'
                                  when 'd' then 'DELETE' else 'ALL' end,
          'role', (select coalesce(string_agg(case when r = 0 then 'public' else pg_get_userbyid(r) end, ', '), '')
                     from unnest(p.polroles) r),
          'using', pg_get_expr(p.polqual, p.polrelid),
          'check', pg_get_expr(p.polwithcheck, p.polrelid)) order by p.polname), '[]')
      from pg_policy p where p.polrelid = t),
    'cizi_klice', (
      select coalesce(jsonb_agg(jsonb_build_object('nazev', conname, 'definice', pg_get_constraintdef(oid))), '[]')
      from pg_constraint where conrelid = t and contype = 'f')
  );
end $$;

-- ---------- čtení řádků (stránkování, hledání, řazení) ----------
create or replace function public.db_admin_radky(
  p_klic text, p_tabulka text,
  p_hledat text default null, p_sloupec text default null,
  p_razeni text default null, p_sestupne boolean default false,
  p_limit int default 50, p_offset int default 0)
returns jsonb language plpgsql security definer
set search_path = public, pg_catalog as $$
declare
  t regclass; kind char; kde text := 'true'; poradi text := ''; celkem bigint; radky jsonb; ct text;
begin
  perform db_admin_ok(p_klic);
  t := db_admin_tab(p_tabulka);
  select relkind into kind from pg_class where oid = t;
  set local statement_timeout = '30s';

  if nullif(p_hledat, '') is not null then
    if nullif(p_sloupec, '') is not null then
      if not exists (select 1 from pg_attribute where attrelid = t and attname = p_sloupec and attnum > 0 and not attisdropped) then
        raise exception 'Sloupec „%“ neexistuje', p_sloupec;
      end if;
      kde := format('_t.%I::text ilike ''%%'' || $1 || ''%%''', p_sloupec);
    else
      kde := '_t::text ilike ''%'' || $1 || ''%''';
    end if;
  end if;

  if nullif(p_razeni, '') is not null then
    if not exists (select 1 from pg_attribute where attrelid = t and attname = p_razeni and attnum > 0 and not attisdropped) then
      raise exception 'Sloupec „%“ neexistuje', p_razeni;
    end if;
    poradi := format('order by _t.%I %s nulls last', p_razeni, case when p_sestupne then 'desc' else 'asc' end);
  elsif kind in ('r','p') then
    poradi := 'order by _t.ctid';
  end if;

  ct := case when kind in ('r','m') then ' || jsonb_build_object(''_ctid'', _t.ctid::text)' else '' end;

  execute format('select count(*) from %s _t where %s', t, kde) into celkem using p_hledat;
  execute format('select coalesce(jsonb_agg(x.j), ''[]'') from (select to_jsonb(_t)%s j from %s _t where %s %s limit %s offset %s) x',
                 ct, t, kde, poradi, least(greatest(coalesce(p_limit, 50), 1), 5000), greatest(coalesce(p_offset, 0), 0))
    into radky using p_hledat;
  return jsonb_build_object('celkem', celkem, 'radky', radky);
end $$;

-- ---------- pomocné: seznam sloupců z klíčů jsonb ----------
create or replace function public.db_admin_cols(t regclass, p_data jsonb, p_bez_pk boolean default false)
returns text[] language sql stable security definer
set search_path = public, pg_catalog as $$
  select coalesce(array_agg(quote_ident(a.attname) order by a.attnum), '{}')
    from pg_attribute a
   where a.attrelid = t and a.attnum > 0 and not a.attisdropped and a.attgenerated = ''
     and a.attname in (select jsonb_object_keys(p_data))
     and (not p_bez_pk or a.attname <> all (db_admin_pk(t)))
$$;

-- podmínka „řádek je stále ten původní“ (porovná primární klíč)
create or replace function public.db_admin_pk_shoda(t regclass)
returns text language sql stable security definer
set search_path = public, pg_catalog as $$
  select coalesce(string_agg(format(' and _t.%I is not distinct from _r.%I', c, c), ''), '')
    from unnest(db_admin_pk(t)) c
$$;

-- ---------- vložení / úprava řádku ----------
-- p_ctid = null  → INSERT; jinak UPDATE řádku s daným ctid (a stejným PK jako p_puvodni)
create or replace function public.db_admin_uloz(
  p_klic text, p_tabulka text, p_data jsonb, p_ctid text default null, p_puvodni jsonb default null)
returns jsonb language plpgsql security definer
set search_path = public, pg_catalog as $$
declare t regclass; cols text[]; vysl jsonb;
begin
  perform db_admin_ok(p_klic);
  t := db_admin_tab(p_tabulka);
  cols := db_admin_cols(t, coalesce(p_data, '{}'));
  if p_ctid is null then
    if cardinality(cols) = 0 then
      execute format('insert into %s as _t default values returning to_jsonb(_t) || jsonb_build_object(''_ctid'', _t.ctid::text)', t)
        into vysl;
    else
      execute format('insert into %s as _t (%s) overriding system value select %2$s from jsonb_populate_record(null::%1$s, $1) '
                     'returning to_jsonb(_t) || jsonb_build_object(''_ctid'', _t.ctid::text)', t, array_to_string(cols, ','))
        into vysl using p_data;
    end if;
  else
    if cardinality(cols) = 0 then raise exception 'Nic ke změně'; end if;
    execute format('update %s as _t set (%s) = (select %2$s from jsonb_populate_record(null::%1$s, $1)) '
                   'from jsonb_populate_record(null::%1$s, $3) _r where _t.ctid = $2::tid %3$s '
                   'returning to_jsonb(_t) || jsonb_build_object(''_ctid'', _t.ctid::text)',
                   t, array_to_string(cols, ','), db_admin_pk_shoda(t))
      into vysl using p_data, p_ctid, coalesce(p_puvodni, '{}');
    if vysl is null then raise exception 'Řádek se mezitím změnil nebo byl smazán – načti data znovu.'; end if;
  end if;
  return vysl;
end $$;

-- ---------- smazání řádků ----------
-- p_radky = pole původních řádků (včetně _ctid)
create or replace function public.db_admin_smaz(p_klic text, p_tabulka text, p_radky jsonb)
returns int language plpgsql security definer
set search_path = public, pg_catalog as $$
declare t regclass; r jsonb; n int := 0; k int;
begin
  perform db_admin_ok(p_klic);
  t := db_admin_tab(p_tabulka);
  for r in select * from jsonb_array_elements(p_radky) loop
    execute format('delete from %s _t using jsonb_populate_record(null::%1$s, $2) _r where _t.ctid = $1::tid %s',
                   t, db_admin_pk_shoda(t))
      using r->>'_ctid', r;
    get diagnostics k = row_count;
    n := n + k;
  end loop;
  return n;
end $$;

-- ---------- hromadný import ----------
-- p_rezim: 'pridat' (INSERT), 'upsert' (INSERT … ON CONFLICT PK DO UPDATE), 'nahradit' (smaže vše a vloží)
create or replace function public.db_admin_import(p_klic text, p_tabulka text, p_radky jsonb, p_rezim text default 'pridat')
returns int language plpgsql security definer
set search_path = public, pg_catalog as $$
declare t regclass; cols text[]; upd text[]; pk text[]; konf text := ''; n int;
begin
  perform db_admin_ok(p_klic);
  t := db_admin_tab(p_tabulka);
  if jsonb_typeof(p_radky) <> 'array' or jsonb_array_length(p_radky) = 0 then return 0; end if;
  set local statement_timeout = '120s';
  cols := db_admin_cols(t, p_radky->0);
  if cardinality(cols) = 0 then raise exception 'Žádný sloupec z importu neodpovídá tabulce'; end if;

  if p_rezim = 'nahradit' then
    execute format('delete from %s', t);
  elsif p_rezim = 'upsert' then
    pk := db_admin_pk(t);
    if cardinality(pk) = 0 then raise exception 'Tabulka nemá primární klíč – upsert nelze použít'; end if;
    select array_agg(format('%s = excluded.%s', c, c)) into upd from unnest(db_admin_cols(t, p_radky->0, true)) c;
    konf := format(' on conflict (%s) do %s',
                   (select string_agg(quote_ident(c), ',') from unnest(pk) c),
                   case when cardinality(upd) > 0 then 'update set ' || array_to_string(upd, ',') else 'nothing' end);
  end if;

  execute format('insert into %s (%s) overriding system value select %2$s from jsonb_populate_recordset(null::%1$s, $1)%3$s',
                 t, array_to_string(cols, ','), konf)
    using p_radky;
  get diagnostics n = row_count;
  return n;
end $$;

-- ---------- SQL konzole ----------
create or replace function public.db_admin_sql(p_klic text, p_sql text)
returns jsonb language plpgsql security definer
set search_path = public, extensions, pg_catalog as $$
declare r record; radky jsonb := '[]'; n bigint := 0; t0 timestamptz := clock_timestamp(); s text;
begin
  perform db_admin_ok(p_klic);
  set local statement_timeout = '60s';
  -- odstranit úvodní komentáře a koncový středník
  s := btrim(p_sql, E' \t\r\n');
  loop
    if left(s, 2) = '--' then
      s := btrim(case when strpos(s, E'\n') > 0 then substr(s, strpos(s, E'\n') + 1) else '' end, E' \t\r\n');
    elsif left(s, 2) = '/*' and strpos(s, '*/') > 0 then
      s := btrim(substr(s, strpos(s, '*/') + 2), E' \t\r\n');
    else exit;
    end if;
  end loop;
  s := regexp_replace(s, ';[ \t\r\n]*$', '');
  if s = '' then raise exception 'Prázdný dotaz'; end if;
  if s ~* '^(select|with|values|table|explain|show)\M' or s ~* '\mreturning\M' then
    for r in execute s loop
      n := n + 1;
      if n <= 2000 then radky := radky || jsonb_build_array(to_jsonb(r)); end if;
    end loop;
    return jsonb_build_object('typ', 'radky', 'radky', radky, 'pocet', n, 'orezano', n > 2000,
                              'ms', round(extract(epoch from clock_timestamp() - t0) * 1000));
  else
    execute s;
    get diagnostics n = row_count;
    return jsonb_build_object('typ', 'prikaz', 'pocet', n,
                              'ms', round(extract(epoch from clock_timestamp() - t0) * 1000));
  end if;
end $$;

-- ---------- údržba a statistiky ----------
create or replace function public.db_admin_udrzba(p_klic text)
returns jsonb language plpgsql security definer
set search_path = public, pg_catalog as $$
declare cron jsonb := null; behy jsonb := null;
begin
  perform db_admin_ok(p_klic);
  begin
    execute $q$select coalesce(jsonb_agg(jsonb_build_object('id', jobid, 'nazev', jobname, 'plan', schedule,
                 'prikaz', command, 'aktivni', active) order by jobid), '[]') from cron.job$q$ into cron;
    execute $q$select coalesce(jsonb_agg(x order by x.zacatek desc), '[]') from (
                 select d.jobid id, j.jobname nazev, d.status stav, d.return_message zprava, d.start_time zacatek,
                        round(extract(epoch from d.end_time - d.start_time) * 1000) ms
                   from cron.job_run_details d left join cron.job j using (jobid)
                  order by d.start_time desc limit 40) x$q$ into behy;
  exception when others then null;
  end;
  return jsonb_build_object(
    'velikost', pg_database_size(current_database()),
    'pripojeni', (select count(*) from pg_stat_activity where datname = current_database()),
    'tabulky', (
      select coalesce(jsonb_agg(jsonb_build_object(
          'nazev', s.relname, 'zive', s.n_live_tup, 'mrtve', s.n_dead_tup,
          'velikost', pg_total_relation_size(s.relid), 'data', pg_relation_size(s.relid),
          'indexy', pg_indexes_size(s.relid),
          'seq_scan', s.seq_scan, 'idx_scan', coalesce(s.idx_scan, 0),
          'vacuum', greatest(s.last_vacuum, s.last_autovacuum),
          'analyze', greatest(s.last_analyze, s.last_autoanalyze),
          'zmeny', s.n_mod_since_analyze) order by pg_total_relation_size(s.relid) desc), '[]')
      from pg_stat_user_tables s where s.schemaname = 'public'),
    'nepouzite_indexy', (
      select coalesce(jsonb_agg(jsonb_build_object('tabulka', s.relname, 'index', s.indexrelname,
          'velikost', pg_relation_size(s.indexrelid)) order by pg_relation_size(s.indexrelid) desc), '[]')
      from pg_stat_user_indexes s join pg_index i using (indexrelid)
      where s.schemaname = 'public' and s.idx_scan = 0 and not i.indisprimary and not i.indisunique),
    'dlouhe_dotazy', (
      select coalesce(jsonb_agg(jsonb_build_object('pid', pid, 'stav', state, 'uzivatel', usename,
          'trvani_s', round(extract(epoch from now() - query_start)), 'dotaz', left(query, 300))), '[]')
      from pg_stat_activity
      where datname = current_database() and state <> 'idle' and pid <> pg_backend_pid()
        and query_start < now() - interval '30 seconds'),
    'bezpecnost', (
      select coalesce(jsonb_agg(x), '[]') from (
        select 'chyba' uroven, format('Tabulka „%s“ nemá zapnuté RLS – je přes API volně čitelná i zapisovatelná.', c.relname) text
          from pg_class c join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'public' and c.relkind in ('r','p') and not c.relrowsecurity
        union all
        select 'info', format('Tabulka „%s“ má RLS bez politik – přes API je přístupná jen přes funkce.', c.relname)
          from pg_class c join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'public' and c.relkind in ('r','p') and c.relrowsecurity
           and not exists (select 1 from pg_policy p where p.polrelid = c.oid)
        union all
        select 'varovani', format('Politika „%s“ na „%s“ povoluje %s komukoli (podmínka true).', p.polname, c.relname,
                                  case p.polcmd when 'a' then 'INSERT' when 'w' then 'UPDATE' when 'd' then 'DELETE' else 'zápis' end)
          from pg_policy p join pg_class c on c.oid = p.polrelid join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'public' and p.polcmd in ('a','w','d','*')
           and (0 = any (p.polroles) or exists (select 1 from unnest(p.polroles) r where pg_get_userbyid(r) = 'anon'))
           and coalesce(pg_get_expr(p.polqual, p.polrelid), pg_get_expr(p.polwithcheck, p.polrelid), 'true') = 'true'
        union all
        select 'varovani', format('Funkce „%s“ je SECURITY DEFINER bez pevného search_path.', p.proname)
          from pg_proc p join pg_namespace n on n.oid = p.pronamespace
         where n.nspname = 'public' and p.prosecdef
           and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) c where c like 'search_path=%')
      ) x),
    'cron', cron,
    'cron_behy', behy
  );
end $$;

-- ANALYZE / REINDEX jedné tabulky (VACUUM nejde spustit uvnitř funkce – běží automaticky)
create or replace function public.db_admin_akce(p_klic text, p_tabulka text, p_akce text)
returns text language plpgsql security definer
set search_path = public, pg_catalog as $$
declare t regclass; t0 timestamptz := clock_timestamp();
begin
  perform db_admin_ok(p_klic);
  t := db_admin_tab(p_tabulka);
  set local statement_timeout = '300s';
  if p_akce = 'analyze' then execute format('analyze %s', t);
  elsif p_akce = 'reindex' then execute format('reindex table %s', t);
  else raise exception 'Neznámá akce %', p_akce;
  end if;
  return format('%s hotovo za %s ms', upper(p_akce), round(extract(epoch from clock_timestamp() - t0) * 1000));
end $$;

-- ---------- práva ----------
revoke all on function public.db_admin_ok(text), public.db_admin_tab(text), public.db_admin_pk(regclass),
  public.db_admin_cols(regclass, jsonb, boolean), public.db_admin_pk_shoda(regclass) from public, anon, authenticated;

revoke all on function public.db_admin_info(text), public.db_admin_struktura(text, text),
  public.db_admin_radky(text, text, text, text, text, boolean, int, int),
  public.db_admin_uloz(text, text, jsonb, text, jsonb), public.db_admin_smaz(text, text, jsonb),
  public.db_admin_import(text, text, jsonb, text), public.db_admin_sql(text, text),
  public.db_admin_udrzba(text), public.db_admin_akce(text, text, text) from public;

grant execute on function public.db_admin_info(text), public.db_admin_struktura(text, text),
  public.db_admin_radky(text, text, text, text, text, boolean, int, int),
  public.db_admin_uloz(text, text, jsonb, text, jsonb), public.db_admin_smaz(text, text, jsonb),
  public.db_admin_import(text, text, jsonb, text), public.db_admin_sql(text, text),
  public.db_admin_udrzba(text), public.db_admin_akce(text, text, text) to anon, authenticated;
