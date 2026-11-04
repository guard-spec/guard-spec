-- Identity hardening (RF-N15 security review).

-- Emails are stored lower-cased and trimmed, and compared that way. Two
-- accounts that differ only in case cannot both survive; the migration stops
-- and names them instead of picking one.
DO $$
DECLARE
    dup TEXT;
BEGIN
    SELECT string_agg(e, ', ') INTO dup FROM (
        SELECT lower(btrim(email)) AS e FROM users GROUP BY lower(btrim(email)) HAVING count(*) > 1
    ) d;
    IF dup IS NOT NULL THEN
        RAISE EXCEPTION 'users differ only in the case or spacing of their email: %. Rename or remove all but one of each, then migrate again', dup;
    END IF;
END
$$;
UPDATE users SET email = lower(btrim(email)) WHERE email <> lower(btrim(email));
ALTER TABLE users ADD CONSTRAINT users_email_normalized CHECK (email = lower(btrim(email)));
UPDATE invites SET email = lower(btrim(email)) WHERE email <> lower(btrim(email));

-- Per-user 2FA failures: after 10 wrong codes in a row the account's second
-- step is locked for 15 minutes, doubling every 5 failures after that (at
-- most 24 hours). A right code resets the count.
ALTER TABLE users
    ADD COLUMN mfa_failures     INT NOT NULL DEFAULT 0,
    ADD COLUMN mfa_locked_until TIMESTAMPTZ;

-- Login CSRF: the state of an SSO login is bound to the browser that started
-- it, through a random cookie whose SHA-256 is kept here. Profile links
-- (link_user_id set) are bound to the user instead, at completion.
ALTER TABLE oidc_states ADD COLUMN browser_hash TEXT;

-- One-time codes also carry a pending identity link: purpose 'link' names the
-- identity (provider, subject, email) that POST /auth/identities/link/complete
-- binds to user_id, the user who started the link, after checking the bearer.
ALTER TABLE oidc_codes
    ADD COLUMN purpose     TEXT NOT NULL DEFAULT 'login' CONSTRAINT oidc_codes_purpose CHECK (purpose IN ('login', 'link')),
    ADD COLUMN provider_id UUID REFERENCES identity_providers(id) ON DELETE CASCADE,
    ADD COLUMN subject     TEXT,
    ADD COLUMN email       TEXT;

-- An SSO login links to an existing account by email only if the provider is
-- trusted for it, and the account has no password and no identity.
ALTER TABLE identity_providers ADD COLUMN trust_email_for_linking BOOLEAN NOT NULL DEFAULT false;

-- Instance facts. bootstrap_admin: the ADMIN_EMAIL bootstrap ran (or an
-- instance administrator already existed), so a deleted bootstrap admin is
-- not created again at the next start.
CREATE TABLE instance_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
GRANT SELECT, INSERT, UPDATE ON instance_state TO guardspec_app;
INSERT INTO instance_state (key, value)
SELECT 'bootstrap_admin', 'migrated' WHERE EXISTS (SELECT 1 FROM users WHERE is_instance_admin);

-- The organizations where uid is the only active owner. Spans organizations
-- (memberships are row-level secured), so it runs with the owner's rights.
CREATE FUNCTION sole_owner_orgs(uid UUID)
RETURNS TABLE (org_id UUID)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
    SELECT m.org_id FROM org_memberships m
    WHERE m.user_id = uid AND m.role = 'owner'
      AND NOT EXISTS (
          SELECT 1 FROM org_memberships o JOIN users u ON u.id = o.user_id
          WHERE o.org_id = m.org_id AND o.role = 'owner' AND o.user_id <> uid AND u.disabled_at IS NULL)
$$;
REVOKE ALL ON FUNCTION sole_owner_orgs(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sole_owner_orgs(UUID) TO guardspec_app;

-- Removes every membership of a deleted user, across organizations.
CREATE FUNCTION delete_user_memberships(uid UUID)
RETURNS INT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    n INT;
BEGIN
    DELETE FROM project_memberships WHERE user_id = uid;
    DELETE FROM org_memberships WHERE user_id = uid;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;
REVOKE ALL ON FUNCTION delete_user_memberships(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION delete_user_memberships(UUID) TO guardspec_app;
