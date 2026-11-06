# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0

# One Secrets Manager secret per value, as a plain string. Terraform creates
# the secrets but never their values, so no secret ends up in the Terraform
# state or plan. Put the values in with the commands in README.md (step 2)
# before the services start.
#
# The RDS owner password is not here: RDS keeps it in its own secret
# (manage_master_user_password in database.tf).

resource "aws_secretsmanager_secret" "app_password" {
  name        = "${var.name}/app-password"
  description = "Password of the guardspec_app database role (PGPASSWORD of both services)."
  kms_key_id  = local.kms_key_arn
}

resource "aws_secretsmanager_secret" "jwt_secret" {
  name        = "${var.name}/jwt-secret"
  description = "JWT_SECRET of the control plane: at least 32 bytes."
  kms_key_id  = local.kms_key_arn
}

resource "aws_secretsmanager_secret" "mfa_enc_key" {
  name        = "${var.name}/mfa-enc-key"
  description = "MFA_ENC_KEY: 32 random bytes in base64. Encrypts TOTP secrets. Not recoverable: keep an offline copy, never rotate automatically."
  kms_key_id  = local.kms_key_arn

  # The longest recovery window: deleting this key by mistake locks out every
  # user with 2FA.
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret" "admin_password" {
  name        = "${var.name}/admin-password"
  description = "ADMIN_PASSWORD of the first owner (used once, at the first start)."
  kms_key_id  = local.kms_key_arn
}

resource "aws_secretsmanager_secret" "upstream_llm_key" {
  count       = local.upstream_key_enabled ? 1 : 0
  name        = "${var.name}/upstream-llm-key"
  description = "UPSTREAM_LLM_KEY: bearer token the gateway sends to UPSTREAM_LLM_URL."
  kms_key_id  = local.kms_key_arn
}
