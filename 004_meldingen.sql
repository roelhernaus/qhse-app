-- ============================================================
-- QHSE-systeem — Migratie 004: Meldingen (+ chat)
-- Plak dit in Supabase → SQL Editor → "New query" → Run
-- ============================================================

-- 1. MELDINGEN
create table meldingen (
  id uuid primary key default gen_random_uuid(),
  organisatie_id uuid not null references organisaties(id) on delete cascade,
  type text not null check (type in ('Onveilige situatie','Incident','Verbetervoorstel')),
  anoniem boolean not null default false,
  omschrijving text not null,
  status text not null default 'Nieuw' check (status in ('Nieuw','In behandeling','Afgehandeld')),
  ernst text not null default 'amber' check (ernst in ('green','amber','red')),
  melder_id uuid references profielen(id) on delete set null,
  actiehouder_id uuid references profielen(id) on delete set null,
  aangemaakt_op timestamptz not null default now()
);

-- 2. CHATBERICHTEN (alleen bij niet-anonieme meldingen, tussen melder en actiehouder)
create table melding_berichten (
  id uuid primary key default gen_random_uuid(),
  melding_id uuid not null references meldingen(id) on delete cascade,
  afzender_id uuid not null references profielen(id) on delete cascade,
  tekst text not null,
  aangemaakt_op timestamptz not null default now()
);

alter table meldingen enable row level security;
alter table melding_berichten enable row level security;

-- ---- MELDINGEN: wie mag wat zien/doen ----

-- Zichtbaar voor: de melder zelf, de actiehouder, of KAM/admin (organisatiebreed overzicht)
create policy "meldingen zichtbaar voor betrokkenen of kam/admin"
  on meldingen for select
  using (
    organisatie_id = huidige_organisatie_id()
    and (
      melder_id = auth.uid()
      or actiehouder_id = auth.uid()
      or huidige_rol() in ('admin','kam')
    )
  );

-- Iedereen mag voor zichzelf een melding aanmaken
create policy "leden kunnen zelf een melding aanmaken"
  on meldingen for insert
  with check (
    organisatie_id = huidige_organisatie_id()
    and melder_id = auth.uid()
  );

-- Bijwerken (bijv. in behandeling nemen, afhandelen) mag de actiehouder of KAM/admin
create policy "actiehouder of kam/admin mag bijwerken"
  on meldingen for update
  using (
    organisatie_id = huidige_organisatie_id()
    and (actiehouder_id = auth.uid() or huidige_rol() in ('admin','kam'))
  );

-- ---- VIEW: verbergt de melder-identiteit écht bij anonieme meldingen ----
-- Iedereen die de rij mag zien (via de policy hierboven) ziet 'melder_id' alleen
-- als hij/zij zelf de melder is. Voor iedereen anders — inclusief admin — wordt
-- het veld null, zodra 'anoniem' = true. Dit is de daadwerkelijke AVG-bescherming,
-- niet alleen een UI-keuze.
create or replace view meldingen_view
with (security_invoker = true)
as
select
  m.id, m.organisatie_id, m.type, m.anoniem, m.omschrijving, m.status, m.ernst,
  case when m.anoniem and m.melder_id is distinct from auth.uid()
       then null else m.melder_id end as melder_id,
  m.actiehouder_id, m.aangemaakt_op
from meldingen m;

-- ---- MELDING_BERICHTEN (chat) ----

-- Chat alleen zichtbaar bij niet-anonieme meldingen, voor melder/actiehouder/kam/admin
create policy "chat zichtbaar voor betrokkenen bij niet-anonieme melding"
  on melding_berichten for select
  using (
    exists (
      select 1 from meldingen m
      where m.id = melding_berichten.melding_id
        and not m.anoniem
        and (m.melder_id = auth.uid() or m.actiehouder_id = auth.uid() or huidige_rol() in ('admin','kam'))
    )
  );

-- Alleen melder of actiehouder mag berichten sturen (niet zomaar iedereen met kam/admin-rol)
create policy "melder of actiehouder mag chatten"
  on melding_berichten for insert
  with check (
    afzender_id = auth.uid()
    and exists (
      select 1 from meldingen m
      where m.id = melding_berichten.melding_id
        and not m.anoniem
        and (m.melder_id = auth.uid() or m.actiehouder_id = auth.uid())
    )
  );
