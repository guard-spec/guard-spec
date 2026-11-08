-- Copyright 2026 The Guard Spec Authors
-- SPDX-License-Identifier: Apache-2.0

-- Sealed content ("gsenc:v1:...") does not decrypt without these keys: run
-- `control-plane keys decrypt-existing` before going down.
DROP FUNCTION IF EXISTS purge_unused_data_keys();
DROP TABLE IF EXISTS org_data_keys;
