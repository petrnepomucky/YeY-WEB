-- =====================================================================
-- Doplněk k db_admin.sql: funkce pro MAZÁNÍ řádků a IMPORT CSV.
-- Spusť v Supabase → SQL Editor v OBOU projektech:
--   Stavební materiál  https://supabase.com/dashboard/project/fvrpuddkarujfttoaavb/sql/new
--   YeY - Online Office https://supabase.com/dashboard/project/hkzhjoveiqadezmvksdz/sql/new
-- (Samotné spuštění nic nemaže – jen vytvoří funkce.)
-- =====================================================================

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

revoke all on function public.db_admin_smaz(text, text, jsonb), public.db_admin_import(text, text, jsonb, text) from public;
grant execute on function public.db_admin_smaz(text, text, jsonb), public.db_admin_import(text, text, jsonb, text) to anon, authenticated;
