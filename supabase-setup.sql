-- Capability Book / Cloud storage v2 — automatic page ownership — run ONCE in this project's Supabase SQL Editor.
-- Safe to run again: no DROP TABLE, no deletion of existing content or Auth users.
-- Pages are PUBLIC. Profiles and membership rows are PRIVATE to their account.
-- Ownership is claimed automatically using authenticated company email/domain; no admin approval.
-- Editable user_metadata alone NEVER grants ownership.
-- Keep the service_role/Secret key OUT of HTML, JavaScript, and chat messages.
BEGIN;

CREATE SCHEMA IF NOT EXISTS book_private;
REVOKE ALL ON SCHEMA book_private FROM PUBLIC, anon, authenticated;

CREATE TABLE IF NOT EXISTS public.app_company_pages (
  page_id smallint PRIMARY KEY CHECK (page_id BETWEEN 1 AND 95),
  email_domain text NOT NULL CHECK (email_domain = lower(email_domain) AND email_domain NOT LIKE '%@%')
);
-- The original application's exact 95-page mapping (including repeated domains).
INSERT INTO public.app_company_pages (page_id,email_domain) VALUES
(1,'azarenergy.com'),(2,'aravalve.com'),(3,'arsen-co.com'),(4,'arvinsanat.com'),(5,'aliaj-joosh.com'),
(6,'pars-pardaz.com'),(7,'pakzy.com'),(8,'sanco.ir'),(9,'pkarvin.com'),(10,'pumpturbine.ir'),
(11,'partosanat.com'),(12,'berkeh.com'),(13,'iipgroup.ir'),(14,'pooladvarzan.com'),(15,'piramoonco.ir'),
(16,'taban.compsore.ci'),(17,'packmangroup.com'),(18,'tasha-co.com'),(19,'tamkar.com'),(20,'gassoco.com'),
(21,'tavanmehvar.ir'),(22,'turbinedar.com'),(23,'gitco.ir'),(24,'saabsteel.com'),(25,'rastagroup.net'),
(26,'mppc.ir'),(27,'hepcoir.com'),(28,'sppc.ir'),(29,'deylmanfilter.com'),(30,'farassan.com'),
(31,'taftanblade.com'),(32,'tivaa.ir'),(33,'jahanayegh.com'),(34,'daboosanat.com'),(35,'ipcd.ir'),
(36,'zagroscompressor.com'),(37,'azarestan.com'),(38,'ciinc.ir'),(39,'sandroos.com'),(40,'parseal.com'),
(41,'sinacontrol.com'),(42,'vb-valves.com'),(43,'azarj.ir'),(44,'azarab.ir'),(45,'navidsahand.com'),
(46,'pumpiran.com'),(47,'pantan.co'),(48,'garmagostar.com'),(49,'bermyco.com'),(50,'mashalkave.com'),
(51,'steam.co.ir'),(52,'farayandbokhar.com'),(53,'pidemco.com'),(54,'ipfarayand.com'),(55,'fatehsanat.com'),
(56,'farabvalve.com'),(57,'farinehmachine.com'),(58,'thermochange.net'),(59,'sharifgr.com'),(60,'karasanat.com'),
(61,'emmc.ir'),(62,'klevers-aryana.com'),(63,'controlafzar.com'),(64,'abanaircooler.com'),(65,'kspcom.net'),
(66,'gastechiran.com'),(67,'ab-band.com'),(68,'pei.ir'),(69,'sadid.ir'),(70,'havayar.com'),
(71,'abaninnotech.com'),(72,'machine-ajza.com'),(73,'psrolling.com'),(74,'machineroll.com'),(75,'msa.ir'),
(76,'tasha-co.com'),(77,'mfs-co.com'),(78,'midhco.com'),(79,'masabpooya.com'),(80,'priamoonco.com'),
(81,'arokobioeng.com'),(82,'saapec.com'),(83,'mah-machine.com'),(84,'pooyeshsakht.com'),(85,'mapnabe.com'),
(86,'mapnasts.com'),(87,'chamaan.com'),(88,'mapnagenerator.com'),(89,'damafin.com'),(90,'klingeran.ir'),
(91,'hatco.ir'),(92,'hava-filter.com'),(93,'hilavis.com'),(94,'euroslotpars.com'),(95,'awring.co')
ON CONFLICT (page_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS public.app_company_memberships (
  page_id smallint PRIMARY KEY REFERENCES public.app_company_pages(page_id),
  user_id uuid NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  assigned_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
CREATE TABLE IF NOT EXISTS public.app_pages (
  page_id smallint PRIMARY KEY REFERENCES public.app_company_pages(page_id),
  content jsonb NOT NULL CHECK (jsonb_typeof(content) = 'object' AND octet_length(content::text) <= 4194304),
  version bigint NOT NULL CHECK (version > 0),
  updated_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
CREATE TABLE IF NOT EXISTS public.app_profiles (
  user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  profile jsonb NOT NULL CHECK (jsonb_typeof(profile) = 'object' AND octet_length(profile::text) <= 12582912),
  version bigint NOT NULL CHECK (version > 0),
  updated_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

ALTER TABLE public.app_company_pages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_company_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_pages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_profiles ENABLE ROW LEVEL SECURITY;

-- Remove broad/default privileges. Browser writes are ONLY through checked RPCs.
REVOKE ALL ON public.app_company_pages, public.app_company_memberships,
  public.app_pages, public.app_profiles FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.app_company_pages, public.app_pages TO anon, authenticated;
GRANT SELECT ON public.app_profiles, public.app_company_memberships TO authenticated;
GRANT ALL ON public.app_company_pages, public.app_company_memberships,
  public.app_pages, public.app_profiles TO service_role;

DROP POLICY IF EXISTS app_directory_public_read ON public.app_company_pages;
CREATE POLICY app_directory_public_read ON public.app_company_pages FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS app_book_public_read ON public.app_pages;
CREATE POLICY app_book_public_read ON public.app_pages FOR SELECT TO anon, authenticated USING (true);
DROP POLICY IF EXISTS app_membership_own_read ON public.app_company_memberships;
CREATE POLICY app_membership_own_read ON public.app_company_memberships FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
DROP POLICY IF EXISTS app_profile_own_read ON public.app_profiles;
CREATE POLICY app_profile_own_read ON public.app_profiles FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);

CREATE OR REPLACE FUNCTION book_private.validate_page(p jsonb)
RETURNS void LANGUAGE plpgsql SET search_path = '' AS $$
DECLARE r integer; c integer; item jsonb; k text;
BEGIN
  IF p IS NULL OR jsonb_typeof(p) <> 'object' OR octet_length(p::text) > 4194304
     OR NOT (p ?& ARRAY['intro','table','tableRows','tableCols','tableMeta','tableStyle','certificates','contacts','styleId'])
     OR (p - ARRAY['intro','table','tableRows','tableCols','tableMeta','tableStyle','certificates','contacts','styleId']) <> '{}'::jsonb THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_PAGE_PAYLOAD';
  END IF;
  IF jsonb_typeof(p->'intro') <> 'string' OR jsonb_typeof(p->'certificates') <> 'string'
     OR jsonb_typeof(p->'table') <> 'array' OR jsonb_typeof(p->'contacts') <> 'array'
     OR jsonb_typeof(p->'tableMeta') <> 'array'
     OR jsonb_typeof(p->'tableRows') <> 'number' OR (p->>'tableRows') !~ '^[0-9]{1,2}$'
     OR jsonb_typeof(p->'tableCols') <> 'number' OR (p->>'tableCols') !~ '^[0-9]{1,2}$'
     OR jsonb_typeof(p->'tableStyle') <> 'number' OR (p->>'tableStyle') !~ '^[1-4]$'
     OR jsonb_typeof(p->'styleId') <> 'number' OR (p->>'styleId') !~ '^([1-9]|10)$' THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_PAGE_FIELDS';
  END IF;
  r := (p->>'tableRows')::integer; c := (p->>'tableCols')::integer;
  IF r NOT BETWEEN 1 AND 12 OR c NOT BETWEEN 1 AND 8
     OR jsonb_array_length(p->'table') <> r*c OR jsonb_array_length(p->'tableMeta') <> r*c
     OR jsonb_array_length(p->'contacts') <> 7 THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_TABLE_DIMENSIONS';
  END IF;
  FOR item IN SELECT value FROM jsonb_array_elements((p->'table') || (p->'contacts')) LOOP
    IF jsonb_typeof(item) <> 'string' THEN
      RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_EDITOR_VALUE';
    END IF;
  END LOOP;
  FOR item IN SELECT value FROM jsonb_array_elements(p->'tableMeta') LOOP
    IF jsonb_typeof(item) <> 'object' OR (item - ARRAY['bg','align']) <> '{}'::jsonb THEN
      RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_CELL_STYLE';
    END IF;
    IF item ? 'align' AND (jsonb_typeof(item->'align') <> 'string' OR item->>'align' NOT IN ('left','right','center')) THEN
      RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_CELL_ALIGNMENT';
    END IF;
    IF item ? 'bg' AND (jsonb_typeof(item->'bg') <> 'string' OR length(item->>'bg') > 40
        OR (item->>'bg') !~* '^(#[0-9a-f]{3,8}|rgba?\([0-9 .,]+\))$') THEN
      RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_CELL_COLOR';
    END IF;
  END LOOP;
END $$;

CREATE OR REPLACE FUNCTION book_private.validate_profile(p jsonb)
RETURNS void LANGUAGE plpgsql SET search_path = '' AS $$
DECLARE item jsonb; k text; maxlen integer; rich jsonb;
BEGIN
  IF p IS NULL OR jsonb_typeof(p) <> 'object' OR octet_length(p::text) > 12582912
     OR NOT (p ?& ARRAY['fullname','role','phone','bio','photo','profileTags'])
     OR (p - ARRAY['fullname','role','phone','bio','photo','profileTags','richText']) <> '{}'::jsonb THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_PROFILE_PAYLOAD';
  END IF;
  FOR k,maxlen IN SELECT * FROM (VALUES ('fullname',200),('role',200),('phone',80),('bio',20000),('photo',12000000)) AS limits(k,n) LOOP
    IF jsonb_typeof(p->k) <> 'string' OR length(p->>k) > maxlen THEN
      RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_PROFILE_FIELD';
    END IF;
  END LOOP;
  IF jsonb_typeof(p->'profileTags') <> 'array' OR jsonb_array_length(p->'profileTags') > 100 THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_PROFILE_TAGS';
  END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(p->'profileTags') LOOP
    IF jsonb_typeof(item) <> 'string' OR length(item #>> '{}') > 200 THEN
      RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_PROFILE_TAG';
    END IF;
  END LOOP;
  -- Optional, backwards-compatible rich text. It stays in this PRIVATE row.
  -- Clients sanitize every HTML read/write; none of it belongs in an Auth JWT.
  IF p ? 'richText' THEN
    rich := p->'richText';
    IF jsonb_typeof(rich) <> 'object' OR (rich - ARRAY['fullname','role','phone','bio','profileTags']) <> '{}'::jsonb THEN
      RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_PROFILE_RICH_TEXT';
    END IF;
    FOR k,maxlen IN SELECT * FROM (VALUES ('fullname',65536),('role',65536),('phone',65536),('bio',524288)) AS limits(k,n) LOOP
      IF rich ? k AND (jsonb_typeof(rich->k) <> 'string' OR octet_length(rich->>k) > maxlen) THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_PROFILE_RICH_FIELD';
      END IF;
    END LOOP;
    IF rich ? 'profileTags' THEN
      IF jsonb_typeof(rich->'profileTags') <> 'array'
         OR jsonb_array_length(rich->'profileTags') <> jsonb_array_length(p->'profileTags') THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_PROFILE_RICH_TAGS';
      END IF;
      FOR item IN SELECT value FROM jsonb_array_elements(rich->'profileTags') LOOP
        IF jsonb_typeof(item) <> 'string' OR octet_length(item #>> '{}') > 32768 THEN
          RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_PROFILE_RICH_TAG';
        END IF;
      END LOOP;
    END IF;
  END IF;
  IF p->>'photo' <> '' AND (p->>'photo') !~* '^data:image/(png|jpeg|webp|gif);base64,[a-z0-9+/=]+$'
     AND NOT ((p->>'photo') ~* '^https://[^[:space:]<>"'']+$' AND length(p->>'photo') <= 2048) THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_PROFILE_PHOTO';
  END IF;
END $$;
REVOKE ALL ON FUNCTION book_private.validate_page(jsonb), book_private.validate_profile(jsonb) FROM PUBLIC, anon, authenticated;

-- Automatic ownership on authenticated use; no per-user administrator approval.
-- The requested page is checked against auth.users.email, NOT user_metadata.
-- Enable Auth "Confirm email" in production: auto-confirmed addresses alone are
-- not proof that the registrant actually controls that company's mailbox.
CREATE OR REPLACE FUNCTION public.app_claim_company_page(p_user_id uuid,p_page_id integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE caller uuid := auth.uid(); account_email text; confirmed_at timestamptz;
        domain text; assigned public.app_company_memberships%ROWTYPE;
BEGIN
  IF caller IS NULL OR p_user_id IS DISTINCT FROM caller THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='APP_ACCOUNT_MISMATCH';
  END IF;
  IF p_page_id IS NULL OR p_page_id NOT BETWEEN 1 AND 95 THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_INVALID_PAGE';
  END IF;
  -- Serialize claims for the same account, including pages with repeated domains.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('capability-claim:'||caller::text,0));
  SELECT * INTO assigned FROM public.app_company_memberships WHERE user_id=caller;
  IF FOUND THEN
    IF assigned.page_id <> p_page_id THEN
      RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='APP_ACCOUNT_ALREADY_ASSIGNED';
    END IF;
    RETURN to_jsonb(assigned);
  END IF;
  SELECT email,email_confirmed_at INTO account_email,confirmed_at FROM auth.users WHERE id=caller;
  IF account_email IS NULL OR confirmed_at IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='APP_EMAIL_CONFIRMATION_REQUIRED';
  END IF;
  SELECT email_domain INTO domain FROM public.app_company_pages WHERE page_id=p_page_id;
  IF domain IS NULL OR split_part(lower(account_email),'@',2) <> domain THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='APP_EMAIL_DOMAIN_MISMATCH';
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(173253,p_page_id);
  SELECT * INTO assigned FROM public.app_company_memberships WHERE page_id=p_page_id FOR UPDATE;
  IF FOUND THEN
    IF assigned.user_id <> caller THEN
      RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='APP_PAGE_ALREADY_ASSIGNED';
    END IF;
    RETURN to_jsonb(assigned);
  END IF;
  INSERT INTO public.app_company_memberships(page_id,user_id)
  VALUES(p_page_id,caller) RETURNING * INTO assigned;
  RETURN to_jsonb(assigned);
END $$;
REVOKE ALL ON FUNCTION public.app_claim_company_page(uuid,integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.app_claim_company_page(uuid,integer) TO authenticated;

-- CAS (compare-and-swap) prevents an offline/stale device overwriting a newer save.
-- p_user_id is REQUIRED so a mid-request account change cannot replay user A's
-- private profile into user B's account.
CREATE OR REPLACE FUNCTION public.app_save_page(p_user_id uuid,p_page_id integer,p_content jsonb,p_base_version bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE caller uuid := auth.uid(); existing public.app_pages%ROWTYPE; result public.app_pages%ROWTYPE;
BEGIN
  IF caller IS NULL OR p_user_id IS DISTINCT FROM caller THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='APP_ACCOUNT_MISMATCH';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.app_company_memberships m WHERE m.page_id=p_page_id AND m.user_id=caller) THEN
    IF EXISTS (SELECT 1 FROM public.app_company_memberships m WHERE m.user_id=caller) THEN
      RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='APP_NOT_PAGE_OWNER';
    END IF;
    -- First save can claim the matching company page without any manual approval.
    PERFORM public.app_claim_company_page(caller,p_page_id);
  END IF;
  IF p_base_version IS NULL OR p_base_version < 0 THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_BASE_VERSION_REQUIRED';
  END IF;
  PERFORM book_private.validate_page(p_content);
  PERFORM pg_catalog.pg_advisory_xact_lock(173253,p_page_id);
  -- Recheck after locking, so a simultaneous administrator reassignment is not
  -- authorized merely because the page metadata sent by the client says so.
  PERFORM 1 FROM public.app_company_memberships m WHERE m.page_id=p_page_id AND m.user_id=caller FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='APP_NOT_PAGE_OWNER'; END IF;
  SELECT * INTO existing FROM public.app_pages WHERE page_id=p_page_id FOR UPDATE;
  IF coalesce(existing.version,0) <> p_base_version THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='APP_VERSION_CONFLICT';
  END IF;
  INSERT INTO public.app_pages(page_id,content,version,updated_at)
  VALUES(p_page_id,p_content,p_base_version+1,statement_timestamp())
  ON CONFLICT(page_id) DO UPDATE SET content=EXCLUDED.content,version=EXCLUDED.version,updated_at=EXCLUDED.updated_at
  RETURNING * INTO result;
  RETURN to_jsonb(result);
END $$;

CREATE OR REPLACE FUNCTION public.app_save_profile(p_user_id uuid,p_profile jsonb,p_base_version bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE caller uuid := auth.uid(); existing public.app_profiles%ROWTYPE; result public.app_profiles%ROWTYPE;
BEGIN
  IF caller IS NULL OR p_user_id IS DISTINCT FROM caller THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='APP_ACCOUNT_MISMATCH';
  END IF;
  IF p_base_version IS NULL OR p_base_version < 0 THEN
    RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='APP_BASE_VERSION_REQUIRED';
  END IF;
  PERFORM book_private.validate_profile(p_profile);
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('capability-profile:'||caller::text,0));
  SELECT * INTO existing FROM public.app_profiles WHERE user_id=caller FOR UPDATE;
  IF coalesce(existing.version,0) <> p_base_version THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='APP_VERSION_CONFLICT';
  END IF;
  INSERT INTO public.app_profiles(user_id,profile,version,updated_at)
  VALUES(caller,p_profile,p_base_version+1,statement_timestamp())
  ON CONFLICT(user_id) DO UPDATE SET profile=EXCLUDED.profile,version=EXCLUDED.version,updated_at=EXCLUDED.updated_at
  RETURNING * INTO result;
  RETURN to_jsonb(result);
END $$;

REVOKE ALL ON FUNCTION public.app_save_page(uuid,integer,jsonb,bigint),
  public.app_save_profile(uuid,jsonb,bigint) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.app_save_page(uuid,integer,jsonb,bigint),
  public.app_save_profile(uuid,jsonb,bigint) TO authenticated;

-- OPTIONAL RECOVERY ONLY, not required for normal registration/login/editing.
-- ADMIN ONLY. To recover an exceptional account, call from SQL Editor:
-- SELECT public.app_admin_assign_company(<actual page number>, '<actual registered business email>');
-- Do not run a placeholder. A candidate-list query is in supabase-owners.sql.
-- With mailer_autoconfirm enabled, an email-looking string is NOT proof of mailbox
-- control. Enable Confirm email in Auth and/or verify the employee independently.
CREATE OR REPLACE FUNCTION public.app_admin_assign_company(p_page_id integer,p_email text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE account auth.users%ROWTYPE; domain text; assigned public.app_company_memberships%ROWTYPE;
BEGIN
  SELECT email_domain INTO domain FROM public.app_company_pages WHERE page_id=p_page_id;
  IF domain IS NULL THEN RAISE EXCEPTION 'APP_INVALID_PAGE'; END IF;
  SELECT * INTO account FROM auth.users WHERE lower(email)=lower(trim(p_email));
  IF account.id IS NULL OR account.email_confirmed_at IS NULL THEN RAISE EXCEPTION 'APP_CONFIRMED_ACCOUNT_REQUIRED'; END IF;
  IF split_part(lower(account.email),'@',2) <> domain THEN RAISE EXCEPTION 'APP_EMAIL_DOMAIN_MISMATCH'; END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(173253,p_page_id);
  INSERT INTO public.app_company_memberships(page_id,user_id) VALUES(p_page_id,account.id)
  ON CONFLICT(page_id) DO NOTHING;
  SELECT * INTO assigned FROM public.app_company_memberships WHERE page_id=p_page_id;
  IF assigned.user_id <> account.id THEN RAISE EXCEPTION 'APP_PAGE_ALREADY_ASSIGNED'; END IF;
  RETURN to_jsonb(assigned);
END $$;
REVOKE ALL ON FUNCTION public.app_admin_assign_company(integer,text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.app_admin_assign_company(integer,text) TO service_role;

COMMENT ON TABLE public.app_pages IS 'Public company page rich-text JSON. Sanitize HTML in every renderer. Writes only through versioned, ownership-checked RPC.';
COMMENT ON TABLE public.app_profiles IS 'PRIVATE personal fields/photo/tags. RLS SELECT own user only. No passwords stored here.';
COMMENT ON TABLE public.app_company_memberships IS 'Automatically claimed company-page ownership checked against auth.users email/domain; never granted solely from editable user_metadata.';
NOTIFY pgrst, 'reload schema';
COMMIT;
