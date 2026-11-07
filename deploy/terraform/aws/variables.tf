# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0

# ---------------------------------------------------------------------------
# Where
# ---------------------------------------------------------------------------

variable "region" {
  description = "AWS region to deploy into."
  type        = string
}

variable "name" {
  description = "Prefix for resource names, secrets and log groups."
  type        = string
  default     = "guard-spec"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.name))
    error_message = "name must be 2-21 lower-case letters, digits or hyphens, starting with a letter."
  }
}

variable "tags" {
  description = "Extra tags for every resource."
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------------
# Network: an existing VPC. This module does not create one.
# ---------------------------------------------------------------------------

variable "vpc_id" {
  description = "Existing VPC. Tasks and the database go in its private subnets."
  type        = string
}

variable "private_subnet_ids" {
  description = "At least two private subnets in different AZs, with a NAT route (image pulls from ghcr.io, the upstream LLM)."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "Give at least two private subnets (RDS and the ALBs need two AZs)."
  }
}

variable "public_subnet_ids" {
  description = "At least two public subnets for the internet-facing ALB of the gateway."
  type        = list(string)

  validation {
    condition     = length(var.public_subnet_ids) >= 2
    error_message = "Give at least two public subnets."
  }
}

variable "gateway_certificate_arn" {
  description = "ACM certificate for the gateway's public host name."
  type        = string
}

variable "admin_certificate_arn" {
  description = "ACM certificate for the admin host name (internal ALB)."
  type        = string
}

variable "admin_host" {
  description = "Host name of the admin UI and control-plane API, such as guard-admin.example.com. Used for PUBLIC_BASE_URL (SSO callbacks)."
  type        = string
}

variable "gateway_ingress_cidrs" {
  description = "Client ranges allowed to reach the public gateway ALB on 443."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "admin_ingress_cidrs" {
  description = "Ranges allowed to reach the internal ALB of the control plane on 443 (VPN, bastion)."
  type        = list(string)
}

variable "metrics_ingress_cidrs" {
  description = "Ranges allowed to scrape /metrics (9090 gateway, 9091 control plane) on the tasks. Empty: nobody."
  type        = list(string)
  default     = []
}

variable "migration_host_security_group_id" {
  description = "Security group of the host that runs the migrations (README, step 3). Empty: add the rule yourself."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------

variable "image_tag" {
  description = "Guard Spec release (image tag) for both services, without the leading v. Pin a digest with the *_image_digest variables."
  type        = string
  default     = "0.3.0"
}

variable "gateway_image" {
  description = "Gateway image repository. guard-spec-gateway-full has the L2 and L3 models inside; guard-spec-gateway has none and runs L1 only on Fargate (no models volume here)."
  type        = string
  default     = "ghcr.io/guard-spec/guard-spec-gateway-full"
}

variable "control_plane_image" {
  description = "Control-plane image repository."
  type        = string
  default     = "ghcr.io/guard-spec/guard-spec-control-plane"
}

variable "gateway_image_digest" {
  description = "Optional sha256:... digest of the gateway image; when set it is used instead of the tag. Take it from cosign verify."
  type        = string
  default     = ""

  validation {
    condition     = var.gateway_image_digest == "" || can(regex("^sha256:[0-9a-f]{64}$", var.gateway_image_digest))
    error_message = "gateway_image_digest must be empty or sha256:<64 hex>."
  }
}

variable "control_plane_image_digest" {
  description = "Optional sha256:... digest of the control-plane image; when set it is used instead of the tag."
  type        = string
  default     = ""

  validation {
    condition     = var.control_plane_image_digest == "" || can(regex("^sha256:[0-9a-f]{64}$", var.control_plane_image_digest))
    error_message = "control_plane_image_digest must be empty or sha256:<64 hex>."
  }
}

variable "cpu_architecture" {
  description = "Fargate CPU architecture: ARM64 or X86_64 (the images are multi-arch)."
  type        = string
  default     = "ARM64"

  validation {
    condition     = contains(["ARM64", "X86_64"], var.cpu_architecture)
    error_message = "cpu_architecture must be ARM64 or X86_64."
  }
}

# ---------------------------------------------------------------------------
# Detection: which layers and which models
# ---------------------------------------------------------------------------

variable "detector_layers" {
  description = "DETECTOR_LAYERS: l1,l2,l3 (all three; needs the gateway-full image) or l1 (rules only, fewer false positives)."
  type        = string
  default     = "l1,l2,l3"

  validation {
    condition     = contains(["l1", "l1,l2", "l1,l3", "l1,l2,l3"], var.detector_layers)
    error_message = "detector_layers must be l1, l1,l2, l1,l3 or l1,l2,l3."
  }
}

variable "l2_model" {
  description = "L2_MODEL as name@version, such as guardspec-classifier@v3b. Empty: the version the image recommends. It must be present in the image."
  type        = string
  default     = ""
}

variable "l3_model" {
  description = "L3_MODEL as name@version. Empty: the version the image recommends."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

variable "gateway_desired_count" {
  description = "Gateway tasks. Keep 0 on the first apply, until the secrets are set and the migrations ran (README)."
  type        = number
  default     = 2
}

variable "control_plane_desired_count" {
  description = "Control-plane tasks. Keep 0 on the first apply, until the secrets are set and the migrations ran (README)."
  type        = number
  default     = 1
}

variable "gateway_cpu" {
  description = "Gateway task CPU units. L1 + L2 + L3: 1024 is a starting point; measure."
  type        = number
  default     = 1024
}

variable "gateway_memory" {
  description = "Gateway task memory (MiB). L1 + L2 + L3 use about 900 MiB right after start."
  type        = number
  default     = 2048
}

variable "control_plane_cpu" {
  description = "Control-plane task CPU units."
  type        = number
  default     = 256
}

variable "control_plane_memory" {
  description = "Control-plane task memory (MiB)."
  type        = number
  default     = 512
}

variable "upstream_llm_url" {
  description = "UPSTREAM_LLM_URL: base URL of the OpenAI-compatible API, such as https://api.openai.com/v1. Empty: stub responses."
  type        = string
  default     = ""
}

variable "admin_email" {
  description = "ADMIN_EMAIL: the first owner and instance administrator, created once."
  type        = string
}

variable "audit_retention_days" {
  description = "AUDIT_RETENTION_DAYS: audit rows older than this are deleted; 0 keeps them."
  type        = number
  default     = 90
}

variable "audit_store_content" {
  description = "AUDIT_STORE_CONTENT: true stores prompt and response text in audit rows for every org. Off by default; see docs/security."
  type        = bool
  default     = false
}

variable "gateway_extra_environment" {
  description = "Extra plain environment variables for the gateway (not secrets), such as OUTPUT_CANARY or UPSTREAM_KEY_ORGS."
  type        = map(string)
  default     = {}
}

variable "control_plane_extra_environment" {
  description = "Extra plain environment variables for the control plane (not secrets)."
  type        = map(string)
  default     = {}
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for both services."
  type        = number
  default     = 30
}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.small"
}

variable "db_engine_version" {
  description = "RDS for PostgreSQL major version (17 is what the project tests)."
  type        = string
  default     = "17"
}

variable "db_allocated_storage" {
  description = "Initial storage (GB); it grows up to db_max_allocated_storage."
  type        = number
  default     = 20
}

variable "db_max_allocated_storage" {
  description = "Storage autoscaling limit (GB)."
  type        = number
  default     = 100
}

variable "db_multi_az" {
  description = "Multi-AZ RDS (costs about twice as much)."
  type        = bool
  default     = false
}

variable "db_backup_retention_days" {
  description = "Automated backup retention (days)."
  type        = number
  default     = 7
}

variable "db_deletion_protection" {
  description = "Deletion protection on the RDS instance. Turn off only to destroy a test stack."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "Optional customer managed KMS key for RDS, Secrets Manager and CloudWatch Logs. Empty: AWS managed keys (CloudWatch Logs then uses its default encryption)."
  type        = string
  default     = ""
}
