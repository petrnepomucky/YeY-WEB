-- =====================================================================
-- Doplněk k db_admin.sql: filtrování dat podle hodnot sloupců
-- (téma / skupina / podskupina v katalogu) pro dbadmin.html.
-- db_admin_data = db_admin_radky + parametr p_filtr {"sloupec": "hodnota"}.
-- =====================================================================

create or replace function public.db_admin_filtr_sql(t regclass, p_filtr jsonb)
returns text language plpgsql stable security definer
set search_path = public, pg_catalog as $$
declare k text; s text := '';
begin
  if p_filtr is null or jsonb_typeof(p_filtr) <> 'object' then return ''; end if;
  for k in select jsonb_object_keys(p_filtr) loop
    if not exists (select 1 from pg_attribute where attrelid = t and attname = k and attnum > 0 and not attisdropped) then
      raise exception 'Sloupec „%“ neexistuje', k;
    end if;
    if jsonb_typeof(p_filtr->k) = 'null' then
      s := s || format(' and _t.%I is null', k);
    else
      s := s || format(' and _t.%I::text = ($2->>%L)', k, k);
    end if;
  end loop;
  return s;
end $$;

create or replace function public.db_admin_data(
  p_klic text, p_tabulka text,
  p_hledat text default null, p_sloupec text default null,
  p_razeni text default null, p_sestupne boolean default false,
  p_limit int default 50, p_offset int default 0, p_filtr jsonb default null)
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
  kde := kde || db_admin_filtr_sql(t, p_filtr);

  if nullif(p_razeni, '') is not null then
    if not exists (select 1 from pg_attribute where attrelid = t and attname = p_razeni and attnum > 0 and not attisdropped) then
      raise exception 'Sloupec „%“ neexistuje', p_razeni;
    end if;
    poradi := format('order by _t.%I %s nulls last', p_razeni, case when p_sestupne then 'desc' else 'asc' end);
  elsif kind in ('r','p') then
    poradi := 'order by _t.ctid';
  end if;

  ct := case when kind in ('r','m') then ' || jsonb_build_object(''_ctid'', _t.ctid::text)' else '' end;

  execute format('select count(*) from %s _t where %s', t, kde) into celkem using p_hledat, p_filtr;
  execute format('select coalesce(jsonb_agg(x.j), ''[]'') from (select to_jsonb(_t)%s j from %s _t where %s %s limit %s offset %s) x',
                 ct, t, kde, poradi, least(greatest(coalesce(p_limit, 50), 1), 5000), greatest(coalesce(p_offset, 0), 0))
    into radky using p_hledat, p_filtr;
  return jsonb_build_object('celkem', celkem, 'radky', radky);
end $$;

-- rozdílné hodnoty sloupce s počty (nabídka filtrů), zúžené fulltextem a nadřazenými filtry
create or replace function public.db_admin_hodnoty(
  p_klic text, p_tabulka text, p_sloupec text, p_filtr jsonb default null, p_hledat text default null)
returns jsonb language plpgsql security definer
set search_path = public, pg_catalog as $$
declare t regclass; kde text := 'true'; vysl jsonb;
begin
  perform db_admin_ok(p_klic);
  t := db_admin_tab(p_tabulka);
  set local statement_timeout = '30s';
  if not exists (select 1 from pg_attribute where attrelid = t and attname = p_sloupec and attnum > 0 and not attisdropped) then
    raise exception 'Sloupec „%“ neexistuje', p_sloupec;
  end if;
  if nullif(p_hledat, '') is not null then kde := '_t::text ilike ''%'' || $1 || ''%'''; end if;
  kde := kde || db_admin_filtr_sql(t, p_filtr);
  execute format('select coalesce(jsonb_agg(jsonb_build_object(''h'', h, ''n'', n) order by h nulls last), ''[]'') from ('
                 'select _t.%I::text h, count(*) n from %s _t where %s group by 1 order by 1 nulls last limit 1000) x',
                 p_sloupec, t, kde)
    into vysl using p_hledat, p_filtr;
  return vysl;
end $$;

revoke all on function public.db_admin_filtr_sql(regclass, jsonb) from public, anon, authenticated;
revoke all on function public.db_admin_data(text, text, text, text, text, boolean, int, int, jsonb),
  public.db_admin_hodnoty(text, text, text, jsonb, text) from public;
grant execute on function public.db_admin_data(text, text, text, text, text, boolean, int, int, jsonb),
  public.db_admin_hodnoty(text, text, text, jsonb, text) to anon, authenticated;
