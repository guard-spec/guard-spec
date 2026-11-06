# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0

# Reference, not yet verified: see README.md.

data "aws_vpc" "this" {
  id = var.vpc_id
}

locals {
  kms_key_arn = var.kms_key_arn == "" ? null : var.kms_key_arn

  gateway_image       = var.gateway_image_digest == "" ? "${var.gateway_image}:${var.image_tag}" : "${var.gateway_image}@${var.gateway_image_digest}"
  control_plane_image = var.control_plane_image_digest == "" ? "${var.control_plane_image}:${var.image_tag}" : "${var.control_plane_image}@${var.control_plane_image_digest}"

  # The services connect as guardspec_app (created by the migrations, password
  # set by deploy/postgres/set-app-password.sh); the password comes from
  # Secrets Manager as PGPASSWORD, so the URL carries none. RDS for
  # PostgreSQL enforces TLS (rds.force_ssl=1 below).
  database_url = "postgres://guardspec_app@${aws_db_instance.this.address}:${aws_db_instance.this.port}/guardspec?sslmode=require"

  # With the model layers asked for, a gateway that cannot load them stops
  # instead of running on L1 alone (the gateway-full image sets this too).
  require_ml = var.detector_layers == "l1" ? "false" : "true"

  upstream_key_enabled = var.upstream_llm_url != ""
}

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "gateway" {
  name              = "/${var.name}/gateway"
  retention_in_days = var.log_retention_days
  kms_key_id        = local.kms_key_arn
}

resource "aws_cloudwatch_log_group" "control_plane" {
  name              = "/${var.name}/control-plane"
  retention_in_days = var.log_retention_days
  kms_key_id        = local.kms_key_arn
}
