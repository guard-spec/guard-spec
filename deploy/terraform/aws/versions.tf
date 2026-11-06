# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0

# Reference, not yet verified: see README.md.

terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # No backend block: configure your own (S3 with state locking is the usual
  # choice) before using this for anything real. The state holds no secret
  # values, but it does hold ARNs, hostnames and the network layout.
}

provider "aws" {
  region = var.region

  default_tags {
    tags = merge({ Project = "guard-spec", ManagedBy = "terraform" }, var.tags)
  }
}
