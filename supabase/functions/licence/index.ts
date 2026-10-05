// =====================================================================
// YeY – funkce `licence` (Supabase Edge Function, Deno)
//
// Akce (POST JSON { akce, ... }):
//   tarify     – ceník a platební údaje pro úvodní stránku (veřejné)
//   objednat   – { ico, email, tarif }  → objednávka s jedinečným VS a QR platbou (veřejné)
//   stav       – { id, token }          → stav objednávky, po zaplacení i licenční klíč (jen kupující)
//   platby     – stáhne nové platby z Fio banky a vydá licence (cron, hlavička x-cron-klic)
//   potvrdit   – { vs, klic }           → ruční potvrzení platby a vydání licence (správce, ADMIN_KLIC)
//   prodlouzit – { vs, klic, exp, poslat } → nový podepsaný klíč s jinou platností (správce, ADMIN_KLIC);
//                exp = "RRRR-MM-DD", nebo null = trvalá licence; poslat = poslat nový klíč e-mailem
//   diag       – { klic }               → kontrola nastavení: formát a správnost LIC_PRIVKEY, e-mail, Fio (správce)
//
// Secrets (Supabase → Edge Functions → Secrets):
//   LIC_PRIVKEY   soukromý klíč ECDSA P-256 – PKCS8 v base64, nebo JWK (JSON)   [povinné]
//   UCET_IBAN     IBAN účtu pro platby, např. CZ6508000000192000145399         [povinné]
//   UCET_CISLO    číslo účtu k zobrazení, např. 19-2000145399/0800              [doporučené]
//   PRIJEMCE      jméno příjemce do QR platby                                   [doporučené]
//   CRON_KLIC     tajný řetězec pro kontrolu plateb (nebo tabulka licence_nastaveni) [volitelné]
//   ADMIN_KLIC    tajný řetězec pro ruční potvrzení platby a prodloužení licence [povinné]
//   FIO_TOKEN     token Fio API (jen čtení) – bez něj jen ruční potvrzování     [volitelné]
//   RESEND_API_KEY, MAIL_OD   odeslání klíče e-mailem přes resend.com           [volitelné]
//   TARIFY        JSON s vlastním ceníkem (jinak výchozí níže)                  [volitelné]
//   APP_URL       adresa aplikace pro odkaz v e-mailu, výchozí https://yey.cz/yey.html
// SUPABASE_URL a SUPABASE_SERVICE_ROLE_KEY doplňuje Supabase sám.
// =====================================================================

type Tarif = { nazev: string; cena: number; dni?: number | null; popis?: string };

const VYCHOZI_TARIFY: Record<string, Tarif> = {
  rok:    { nazev: "Roční licence",  cena: 990,  dni: 365,  popis: "Plná verze na 12 měsíců" },
  trvala: { nazev: "Trvalá licence", cena: 2490, dni: null, popis: "Jednorázově, bez dalších poplatků" },
};

const env = (k: string, v = "") => (Deno.env.get(k) ?? v).trim();

function tarify(): Record<string, Tarif> {
  try { const t = JSON.parse(env("TARIFY")); if (t && typeof t === "object") return t; } catch (_) { /* výchozí */ }
  return VYCHOZI_TARIFY;
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-cron-klic",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { ...CORS, "Content-Type": "application/json; charset=utf-8" } });
const chyba = (zprava: string, status = 400) => json({ ok: false, chyba: zprava }, status);

// ---------------------------------------------------------------- databáze (PostgREST, service role)
async function db(cesta: string, init: RequestInit = {}) {
  const url = env("SUPABASE_URL").replace(/\/+$/, "") + "/rest/v1/" + cesta;
  const key = env("SUPABASE_SERVICE_ROLE_KEY");
  const r = await fetch(url, {
    ...init,
    headers: { apikey: key, Authorization: "Bearer " + key, "Content-Type": "application/json",
      Prefer: "return=representation", ...(init.headers || {}) },
  });
  const text = await r.text();
  if (!r.ok) throw new Error("DB " + r.status + ": " + text.slice(0, 200));
  return text ? JSON.parse(text) : null;
}

// ---------------------------------------------------------------- pomocné
export function icoPlatne(ico: string): boolean {
  if (!/^\d{8}$/.test(ico)) return false;
  let s = 0;
  for (let i = 0; i < 7; i++) s += Number(ico[i]) * (8 - i);
  const c = (11 - (s % 11)) % 10;
  return c === Number(ico[7]);
}
const emailPlatny = (e: string) => /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(e);
const nahodny = (n = 24) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => b.toString(16).padStart(2, "0")).join("");
const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const bezDia = (s: string) => s.normalize("NFD").replace(/[̀-ͯ]/g, "");

/** Řetězec QR platby (formát SPD 1.0, Česká bankovní asociace). */
export function spd(iban: string, castka: number, vs: string | number, zprava: string, prijemce = ""): string {
  const cist = (s: string, max: number) => bezDia(s).replace(/\*/g, " ").toUpperCase().slice(0, max);
  const casti = ["SPD*1.0", "ACC:" + iban.replace(/\s/g, ""), "AM:" + castka.toFixed(2), "CC:CZK", "X-VS:" + vs, "MSG:" + cist(zprava, 60)];
  if (prijemce) casti.push("RN:" + cist(prijemce, 35));
  return casti.join("*");
}

async function ares(ico: string): Promise<string | null> {
  try {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 3500);
    const r = await fetch("https://ares.gov.cz/ekonomicke-subjekty-v-be/rest/ekonomicke-subjekty/" + ico, { signal: ctl.signal, headers: { Accept: "application/json" } });
    clearTimeout(t);
    if (!r.ok) return null;
    const d = await r.json();
    return d?.obchodniJmeno || null;
  } catch (_) { return null; }
}

// ---------------------------------------------------------------- podpis licence (stejný formát, jaký ověřuje aplikace)
// Veřejný klíč z aplikace (LIC_PUBKEY v yey.html/offline.html) – podle něj se ověří, že LIC_PRIVKEY je ten správný.
const APP_PUBKEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyNzA+1pzB++SnyN8AXf2ButTdYdKkZngV1I2LP7iuq1yBcqnAgDtGNsKOAKwKeeiA4yJdTe1nylEYhj/1NXEWQ==";
const ALG = { name: "ECDSA", namedCurve: "P-256" };
const zB64 = (s: string) => { s = s.replace(/-/g, "+").replace(/_/g, "/").replace(/[^A-Za-z0-9+/]/g, ""); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); };
const zHex = (s: string) => Uint8Array.from(s.match(/../g)!.map((h) => parseInt(h, 16)));
function pubXY(): { x: string; y: string } {
  const spki = zB64(env("LIC_PUBKEY") || APP_PUBKEY), bod = spki.slice(spki.length - 64);   // 04 || x || y
  return { x: b64u(bod.slice(0, 32)), y: b64u(bod.slice(32)) };
}
const jwkZd = (d: Uint8Array) => ({ kty: "EC", crv: "P-256", d: b64u(d), ...pubXY(), ext: true });

/** Načte LIC_PRIVKEY v jakékoli běžné podobě: PEM, PKCS8 (base64/base64url/hex), SEC1 „EC PRIVATE KEY“, JWK, holé „d“ (32 B). */
export async function nactiKlic(raw: string): Promise<{ klic: CryptoKey; format: string }> {
  let s = raw.trim().replace(/^['"`]+|['"`]+$/g, "").replace(/\\n/g, "\n").trim();
  if (s.startsWith("{")) {
    const j = JSON.parse(s); const jwk = { kty: "EC", crv: "P-256", ...pubXY(), ...j, key_ops: undefined, ext: true };
    return { klic: await crypto.subtle.importKey("jwk", jwk, ALG, false, ["sign"]), format: "JWK" };
  }
  const sec1 = /BEGIN EC PRIVATE KEY/.test(s);
  const telo = s.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  const b = /^[0-9a-fA-F]+$/.test(telo) && telo.length % 2 === 0 && telo.length >= 64 ? zHex(telo) : zB64(telo);
  if (b.length === 32) return { klic: await crypto.subtle.importKey("jwk", jwkZd(b), ALG, false, ["sign"]), format: "surový klíč (32 B)" };
  if (!sec1) { try { return { klic: await crypto.subtle.importKey("pkcs8", b, ALG, false, ["sign"]), format: "PKCS8" }; } catch (_) { /* zkusit SEC1 */ } }
  // SEC1: 30 .. 02 01 01 04 20 <d 32 B>
  for (let i = 0; i + 36 < b.length; i++) if (b[i] === 2 && b[i + 1] === 1 && b[i + 2] === 1 && b[i + 3] === 4 && b[i + 4] === 32)
    return { klic: await crypto.subtle.importKey("jwk", jwkZd(b.slice(i + 5, i + 37)), ALG, false, ["sign"]), format: "SEC1 (EC PRIVATE KEY)" };
  throw new Error("LIC_PRIVKEY má neznámý formát (" + b.length + " B).");
}
/** Ověří, že podpis tímto klíčem projde veřejným klíčem v aplikaci. */
async function sedi(klic: CryptoKey): Promise<boolean> {
  const pub = await crypto.subtle.importKey("spki", zB64(env("LIC_PUBKEY") || APP_PUBKEY), ALG, false, ["verify"]);
  const data = new TextEncoder().encode("yey-test");
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, klic, data);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, sig, data);
}
let _klic: Promise<CryptoKey> | null = null, _klicRaw = "";
function soukromyKlic(): Promise<CryptoKey> {
  const raw = env("LIC_PRIVKEY");
  if (!raw) throw new Error("Chybí secret LIC_PRIVKEY.");
  if (_klic && _klicRaw === raw) return _klic;
  _klicRaw = raw;
  _klic = (async () => {
    const { klic } = await nactiKlic(raw);
    if (!(await sedi(klic))) throw new Error("LIC_PRIVKEY nepatří k veřejnému klíči v aplikaci – aplikace by licenci odmítla.");
    return klic;
  })();
  _klic.catch(() => { _klic = null; });
  return _klic;
}
export async function podepis(payload: Record<string, unknown>): Promise<string> {
  const p = b64u(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, await soukromyKlic(), new TextEncoder().encode(p)));
  return p + "." + b64u(sig);
}

async function posliEmail(o: any, prodlouzeni = false) {
  const key = env("RESEND_API_KEY"), od = env("MAIL_OD");
  if (!key || !od || !o.email || !o.licence) return false;
  const app = env("APP_URL", "https://yey.cz/yey.html");
  const text = [
    "Dobrý den,", "",
    prodlouzeni
      ? "posíláme nový licenční klíč YeY s upravenou platností (IČO " + o.ico + "). Původní klíč prosím nahraďte tímto."
      : "děkujeme za zaplacení licence YeY (" + (tarify()[o.tarif]?.nazev || o.tarif) + ", IČO " + o.ico + ").", "",
    "Aktivace jedním klikem:", app + "#licence=" + o.licence, "",
    "Nebo klíč zkopírujte do aplikace (Nastavení → Licence):", o.licence, "",
    o.exp ? "Licence platí do " + o.exp + "." : "Licence je trvalá.", "",
    "Variabilní symbol platby: " + o.vs, "", "YeY – Kancelář pro řemeslníky",
  ].join("\n");
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST", headers: { Authorization: "Bearer " + key, "Content-Type": "application/json" },
    body: JSON.stringify({ from: od, to: [o.email], subject: (prodlouzeni ? "Nový licenční klíč YeY – IČO " : "Licenční klíč YeY – IČO ") + o.ico, text }),
  });
  return r.ok;
}

/** Podepsaný obsah licence pro objednávku. */
function obsahLicence(o: any, exp: string | null): Record<string, unknown> {
  const payload: Record<string, unknown> = { ico: o.ico, tarif: o.tarif, vs: String(o.vs), iat: new Date().toISOString().slice(0, 10) };
  if (o.firma) payload.firma = o.firma;
  if (exp) payload.exp = exp;
  return payload;
}

/** Vydá licenci k zaplacené objednávce (idempotentní). */
async function vydej(o: any, platbaId: string | null) {
  if (o.stav === "vydano" && o.licence) return o;
  const t = tarify()[o.tarif];
  const exp = t && t.dni ? new Date(Date.now() + t.dni * 864e5).toISOString().slice(0, 10) : null;
  const licence = await podepis(obsahLicence(o, exp));
  const [u] = await db("licence_objednavky?id=eq." + o.id + "&stav=in.(ceka,zaplaceno)", {
    method: "PATCH",
    body: JSON.stringify({ stav: "vydano", licence, exp, platba_id: platbaId ?? o.platba_id ?? null,
      zaplaceno_at: o.zaplaceno_at ?? new Date().toISOString(), vydano_at: new Date().toISOString() }),
  });
  const hotovo = u || o;
  if (u && !u.email_odeslan) {
    try { if (await posliEmail(u)) await db("licence_objednavky?id=eq." + u.id, { method: "PATCH", body: JSON.stringify({ email_odeslan: true }) }); }
    catch (_) { /* e-mail je bonus, klíč je i na stránce */ }
  }
  return hotovo;
}

// ---------------------------------------------------------------- akce
async function akceObjednat(b: any) {
  const ico = String(b.ico || "").replace(/\s/g, "");
  const email = String(b.email || "").trim().toLowerCase();
  const tarifKlic = String(b.tarif || "");
  const t = tarify()[tarifKlic];
  if (!icoPlatne(ico)) return chyba("IČO nemá platný tvar (8 číslic s kontrolní číslicí).");
  if (!emailPlatny(email)) return chyba("Zkontrolujte e-mail.");
  if (!t) return chyba("Neznámý tarif.");
  const iban = env("UCET_IBAN");
  if (!iban) return chyba("Platby zatím nejsou nastavené.", 503);

  // ochrana proti zahlcení: max. 5 nezaplacených objednávek na e-mail za hodinu
  const hodina = new Date(Date.now() - 3600e3).toISOString();
  const posledni = await db("licence_objednavky?select=id&email=eq." + encodeURIComponent(email) + "&stav=eq.ceka&created_at=gt." + hodina);
  if ((posledni || []).length >= 5) return chyba("Příliš mnoho objednávek. Zkuste to prosím za chvíli.", 429);

  const firma = await ares(ico);
  const token = nahodny();
  const [o] = await db("licence_objednavky", { method: "POST",
    body: JSON.stringify({ ico, email, tarif: tarifKlic, castka: t.cena, token, firma }) });
  const zprava = "YeY licence ICO " + ico;
  return json({ ok: true, id: o.id, token, vs: String(o.vs), castka: Number(o.castka), tarif: tarifKlic, nazev: t.nazev,
    firma, iban, ucet: env("UCET_CISLO") || iban, prijemce: env("PRIJEMCE"), zprava,
    spd: spd(iban, Number(o.castka), o.vs, zprava, env("PRIJEMCE")) });
}

async function akceStav(b: any) {
  const id = String(b.id || ""), token = String(b.token || "");
  if (!/^[0-9a-f-]{36}$/.test(id) || !token) return chyba("Neplatný dotaz.");
  const [o] = await db("licence_objednavky?select=*&id=eq." + id + "&token=eq." + encodeURIComponent(token));
  if (!o) return chyba("Objednávka nenalezena.", 404);
  return json({ ok: true, stav: o.stav, vs: String(o.vs), castka: Number(o.castka), tarif: o.tarif, ico: o.ico, firma: o.firma,
    exp: o.exp, licence: o.stav === "vydano" ? o.licence : null, emailOdeslan: o.email_odeslan });
}

/** Stáhne nové pohyby z Fio API, uloží je a spáruje s čekajícími objednávkami. */
async function akcePlatby() {
  const token = env("FIO_TOKEN");
  let nacteno = 0, fioUcet: string | null = null, pohybu = 0;
  if (token) {
    // pohyby za posledních 14 dní (bez „zarážky“ – ta u nového tokenu míří na začátek účtu a Fio pak vrací 422;
    // starší než 90 dní by chtěla silné ověření). Duplicity se při ukládání přeskočí.
    const den = (d: Date) => d.toISOString().slice(0, 10);
    const od = den(new Date(Date.now() - 14 * 864e5)), do_ = den(new Date());
    const r = await fetch("https://fioapi.fio.cz/v1/rest/periods/" + token + "/" + od + "/" + do_ + "/transactions.json");
    if (r.status === 409) return json({ ok: false, chyba: "Fio API: příliš časté volání (max. 1× za 30 s)." }, 429);
    if (!r.ok) { let x = ""; try { x = (await r.text()).slice(0, 200); } catch (_) { /* */ } return json({ ok: false, chyba: "Fio API " + r.status + (x ? ": " + x : "") }, 502); }
    const d = await r.json();
    const pohyby = d?.accountStatement?.transactionList?.transaction || [];
    const info = d?.accountStatement?.info || {};
    fioUcet = info.accountId ? info.accountId + "/" + (info.bankId || "") : null; pohybu = pohyby.length;
    const radky = pohyby.map((p: any) => ({
      id: String(p.column22?.value ?? ""), datum: String(p.column0?.value ?? "").slice(0, 10) || null,
      castka: Number(p.column1?.value ?? 0), mena: p.column14?.value ?? "CZK",
      vs: p.column5?.value != null ? String(p.column5.value).replace(/^0+/, "") : null,
      protiucet: [p.column2?.value, p.column3?.value].filter(Boolean).join("/") || null,
      zprava: p.column16?.value ?? p.column25?.value ?? null,
    })).filter((x: any) => x.id && x.castka > 0);
    if (radky.length) {
      await db("licence_platby?on_conflict=id", { method: "POST", headers: { Prefer: "resolution=ignore-duplicates,return=minimal" }, body: JSON.stringify(radky) });
      nacteno = radky.length;
    }
  }
  // párování: nepřiřazené platby × čekající objednávky podle VS a částky
  const platby = await db("licence_platby?select=*&objednavka=is.null&vs=not.is.null&mena=eq.CZK");
  let vydano = 0; const chyby: string[] = [];
  for (const p of platby || []) {
    const [o] = await db("licence_objednavky?select=*&vs=eq." + encodeURIComponent(p.vs) + "&stav=in.(ceka,zaplaceno)");
    if (!o) continue;
    if (Number(p.castka) + 0.001 < Number(o.castka)) continue;          // nedoplatek – nechat na ručním řešení
    try { await vydej(o, p.id); }
    catch (e) { console.error("Licenci k VS " + p.vs + " se nepodařilo vydat:", e); chyby.push("VS " + p.vs + ": " + (e instanceof Error ? e.message : String(e))); continue; }
    await db("licence_platby?id=eq." + encodeURIComponent(p.id), { method: "PATCH", body: JSON.stringify({ objednavka: o.id }) });
    vydano++;
  }
  return json({ ok: chyby.length === 0, nacteno, vydano, fioUcet, pohybu, fioToken: !!token, ...(chyby.length ? { chyba: chyby.join("; ") } : {}) });
}

async function akcePotvrdit(b: any) {
  const [o] = await db("licence_objednavky?select=*&vs=eq." + encodeURIComponent(String(b.vs || "")));
  if (!o) return chyba("Objednávka s tímto VS neexistuje.", 404);
  const hotovo = await vydej(o, b.platba_id ? String(b.platba_id) : "rucne");
  return json({ ok: true, vs: String(hotovo.vs), stav: hotovo.stav, licence: hotovo.licence, exp: hotovo.exp });
}

/** Nový podepsaný klíč s jinou platností k už vydané licenci (prodloužení, převod na trvalou). */
async function akceProdlouzit(b: any) {
  const [o] = await db("licence_objednavky?select=*&vs=eq." + encodeURIComponent(String(b.vs || "")));
  if (!o) return chyba("Objednávka s tímto VS neexistuje.", 404);
  if (o.stav !== "vydano") return chyba("Licence k této objednávce ještě nebyla vydaná – nejdřív potvrďte platbu.");
  let exp: string | null = null;
  if (b.exp != null && b.exp !== "") {
    exp = String(b.exp);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(exp) || isNaN(new Date(exp + "T00:00:00Z").getTime())) return chyba("Datum musí být ve tvaru RRRR-MM-DD.");
  }
  const licence = await podepis(obsahLicence(o, exp));
  const [u] = await db("licence_objednavky?id=eq." + o.id, {
    method: "PATCH", body: JSON.stringify({ licence, exp, vydano_at: new Date().toISOString() }),
  });
  let emailOdeslan = false;
  if (b.poslat) {
    try { emailOdeslan = await posliEmail(u, true); } catch (_) { emailOdeslan = false; }
  }
  return json({ ok: true, vs: String(u.vs), ico: u.ico, email: u.email, licence: u.licence, exp: u.exp, emailOdeslan });
}

/** Klíč pro automatickou kontrolu plateb: secret CRON_KLIC, nebo hodnota v tabulce licence_nastaveni (klic = 'cron'). */
async function cronOk(k: string | null): Promise<boolean> {
  if (!k) return false;
  if (env("CRON_KLIC") && k === env("CRON_KLIC")) return true;
  try { const [r] = await db("licence_nastaveni?select=hodnota&klic=eq.cron"); return !!r && r.hodnota === k; } catch (_) { return false; }
}

// ---------------------------------------------------------------- vstup
export async function obsluha(req: Request): Promise<Response> {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return chyba("Použijte POST.", 405);
  let b: any = {};
  try { b = await req.json(); } catch (_) { return chyba("Neplatný JSON."); }
  try {
    switch (b.akce) {
      case "tarify": {
        const t = tarify();
        return json({ ok: true, tarify: t, ucet: env("UCET_CISLO") || env("UCET_IBAN"), platbyAktivni: !!env("UCET_IBAN") });
      }
      case "objednat": return await akceObjednat(b);
      case "stav":     return await akceStav(b);
      case "platby": {
        const k = req.headers.get("x-cron-klic") || b.klic;
        if (!(await cronOk(k))) return chyba("Nepovoleno.", 401);
        return await akcePlatby();
      }
      case "diag": {                                       // kontrola nastavení (jen správce)
        if (!env("ADMIN_KLIC") || b.klic !== env("ADMIN_KLIC")) return chyba("Nepovoleno.", 401);
        const v: Record<string, unknown> = {};
        try { const r = await nactiKlic(env("LIC_PRIVKEY")); v.licKlic = r.format; v.licKlicSediSAplikaci = await sedi(r.klic); }
        catch (e) { v.licKlic = "CHYBA: " + (e instanceof Error ? e.message : String(e)); }
        v.email = !!env("RESEND_API_KEY") && !!env("MAIL_OD"); v.mailOd = env("MAIL_OD"); v.appUrl = env("APP_URL", "https://yey.cz/yey.html");
        v.fio = !!env("FIO_TOKEN"); v.ucet = env("UCET_CISLO") || env("UCET_IBAN"); v.tarify = Object.keys(tarify());
        return json({ ok: true, ...v });
      }
      case "potvrdit":
        if (!env("ADMIN_KLIC") || b.klic !== env("ADMIN_KLIC")) return chyba("Nepovoleno.", 401);
        return await akcePotvrdit(b);
      case "prodlouzit":
        if (!env("ADMIN_KLIC") || b.klic !== env("ADMIN_KLIC")) return chyba("Nepovoleno – špatný admin klíč licence (ADMIN_KLIC).", 401);
        return await akceProdlouzit(b);
      default: return chyba("Neznámá akce.");
    }
  } catch (e) {
    console.error(e);
    return chyba("Chyba serveru: " + (e instanceof Error ? e.message : String(e)), 500);
  }
}

// Spuštění serveru (testy si ho vypnou nastavením globalThis.__LICENCE_TEST)
if (!(globalThis as any).__LICENCE_TEST) Deno.serve(obsluha);
