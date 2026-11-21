-- OPTIONAL diagnostic report after supabase-setup.sql (SQL Editor only).
-- No per-user administrator approval or manual assignment is required.
-- app_claim_company_page automatically binds a signed-in account to its valid
-- company page, and app_save_page performs the same check on first save.
-- Existing owners are preserved; another account cannot take an occupied page.
SELECT p.page_id,p.email_domain,m.user_id AS owner_user_id,u.email AS owner_email,
       CASE WHEN m.user_id IS NULL THEN 'automatically assigned at first valid sign-in/use'
            ELSE 'active owner; no approval needed' END AS ownership_status
FROM public.app_company_pages p
LEFT JOIN public.app_company_memberships m ON m.page_id=p.page_id
LEFT JOIN auth.users u ON u.id=m.user_id
ORDER BY p.page_id;

-- Auth's Confirm email setting is independent of administrator approval.
-- Enable it in production so a company-looking email string is actually verified.
-- The legacy app_admin_assign_company helper remains restricted to SQL Editor /
-- service_role for exceptional recovery, but is NOT part of the normal user flow.
-- Pages 18 and 76 share a domain in the original mapping; registration page choice
-- selects which page the account claims, still with one page per account.
