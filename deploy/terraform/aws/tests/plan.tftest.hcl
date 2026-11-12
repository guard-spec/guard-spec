# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0

# terraform test: plans against a mocked AWS provider (no account, no
# credentials, nothing created). It checks the wiring of this module, not
# that AWS accepts it.

mock_provider "aws" {
  mock_data "aws_vpc" {
    defaults = {
      cidr_block = "10.0.0.0/16"
    }
  }
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  region                  = "eu-west-1"
  vpc_id                  = "vpc-0123456789abcdef0"
  private_subnet_ids      = ["subnet-0aaaaaaaaaaaaaaaa", "subnet-0bbbbbbbbbbbbbbbb"]
  public_subnet_ids       = ["subnet-0cccccccccccccccc", "subnet-0dddddddddddddddd"]
  gateway_certificate_arn = "arn:aws:acm:eu-west-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
  admin_certificate_arn   = "arn:aws:acm:eu-west-1:123456789012:certificate/11111111-1111-1111-1111-111111111111"
  admin_host              = "guard-admin.example.com"
  admin_ingress_cidrs     = ["10.0.0.0/16"]
  admin_email             = "admin@example.com"
  upstream_llm_url        = "https://api.example.com/v1"
}

run "defaults" {
  command = plan

  assert {
    condition     = local.gateway_image == "ghcr.io/guard-spec/guard-spec-gateway-full:0.7.0"
    error_message = "the gateway defaults to the gateway-full image of the release"
  }
  assert {
    condition     = local.gateway_environment["DETECTOR_REQUIRE_ML"] == "true" && local.gateway_environment["AUDIT_STORE_CONTENT"] == "false"
    error_message = "model layers required, no content in audit rows by default"
  }
  assert {
    condition     = local.gateway_environment["UPSTREAM_ALLOW_PRIVATE"] == "false"
    error_message = "org upstreams stay off private addresses"
  }
  assert {
    condition     = length(aws_secretsmanager_secret.upstream_llm_key) == 1 && length(local.gateway_secrets) == 2
    error_message = "an upstream URL brings its key secret"
  }
  assert {
    condition     = aws_db_instance.this.storage_encrypted && !aws_db_instance.this.publicly_accessible && aws_db_instance.this.manage_master_user_password
    error_message = "RDS is encrypted, private and keeps the owner password in Secrets Manager"
  }
  assert {
    condition     = aws_lb.control_plane.internal && !aws_lb.gateway.internal
    error_message = "only the gateway is internet-facing"
  }
  assert {
    condition     = local.control_plane_environment["TRUSTED_PROXIES"] == "10.0.0.0/16"
    error_message = "the control plane trusts the VPC range (the internal ALB)"
  }
}

run "rules_only_pinned_digest" {
  command = plan

  variables {
    gateway_image        = "ghcr.io/guard-spec/guard-spec-gateway"
    gateway_image_digest = "sha256:948d14a0441e40a97ef83dd4824c4ffb146817e72fa125a3dab711af27b62729"
    detector_layers      = "l1"
    upstream_llm_url     = ""
  }

  assert {
    condition     = local.gateway_image == "ghcr.io/guard-spec/guard-spec-gateway@sha256:948d14a0441e40a97ef83dd4824c4ffb146817e72fa125a3dab711af27b62729"
    error_message = "a digest wins over the tag"
  }
  assert {
    condition     = local.gateway_environment["DETECTOR_REQUIRE_ML"] == "false"
    error_message = "rules only does not require the model layers"
  }
  assert {
    condition     = length(aws_secretsmanager_secret.upstream_llm_key) == 0 && length(local.gateway_secrets) == 1
    error_message = "no upstream URL, no key secret"
  }
}

run "bad_layers_rejected" {
  command = plan

  variables {
    detector_layers = "l2"
  }

  expect_failures = [var.detector_layers]
}
