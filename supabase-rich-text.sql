-- Optional private rich-text profile extension. Run ONCE on an already installed book.
-- New installations: run supabase-setup.sql instead (it already includes this).
-- No public profile access, credential changes, ownership changes or data rewrite.
BEGIN;
DO $$ BEGIN
 IF to_regclass('public.app_profiles') IS NULL OR to_regnamespace('book_private') IS NULL THEN
  RAISE EXCEPTION 'Run the complete supabase-setup.sql first.';
 END IF;
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
REVOKE ALL ON FUNCTION book_private.validate_profile(jsonb) FROM PUBLIC, anon, authenticated;
COMMIT;
