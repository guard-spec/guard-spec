-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Retention of the activity log and of ended sessions (RF-62d40744). The
-- control plane's retention job (internal/retention) runs them after
-- purge_audit_rows (007), under the same advisory lock.

-- activity_log is row-level secured and holds rows of every org plus
-- instance-level rows (org_id NULL), which guardspec_app sees only with
-- app.org_id or app.instance_scope set. Like purge_audit_rows, the batch
-- delete runs with the owner's rights; it removes at most batch rows older
-- than cutoff and returns how many it removed. idx_activity_log_org leads
-- with org_id, so a cutoff across every org needs its own index.
CREATE INDEX idx_activity_log_at ON activity_log (at);

CREATE FUNCTION purge_activity_rows(cutoff TIMESTAMPTZ, batch INT)
RETURNS INT
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, pg_temp
AS $$
DECLARE
    n INT;
BEGIN
    IF batch IS NULL OR batch < 1 OR batch > 100000 THEN
        RAISE EXCEPTION 'batch must be between 1 and 100000';
    END IF;
    DELETE FROM activity_log WHERE id IN (
        SELECT id FROM activity_log WHERE at < cutoff
        ORDER BY at LIMIT batch
        FOR UPDATE SKIP LOCKED
    );
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END
$$;
REVOKE ALL ON FUNCTION purge_activity_rows(TIMESTAMPTZ, INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_activity_rows(TIMESTAMPTZ, INT) TO guardspec_app;

-- sessions is keyed by user and not row-level secured (013), so
-- guardspec_app deletes ended sessions itself: revoked_at < cutoff OR
-- expires_at < cutoff, never an active one. expires_at has
-- idx_sessions_expires (013); this partial index covers revoked sessions
-- that have not expired yet.
CREATE INDEX idx_sessions_revoked ON sessions (revoked_at) WHERE revoked_at IS NOT NULL;
