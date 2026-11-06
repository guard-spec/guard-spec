# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0

# Security groups. Nothing reaches the control plane from the internet, and
# nothing reaches /metrics unless metrics_ingress_cidrs says so.
#
#   clients  --443-->  public ALB    --8080-->  gateway tasks        --5432--> RDS
#   VPN      --443-->  internal ALB  --8081-->  control-plane tasks  --5432--> RDS

resource "aws_security_group" "public_alb" {
  name        = "${var.name}-public-alb"
  description = "Public ALB of the gateway"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "internal_alb" {
  name        = "${var.name}-internal-alb"
  description = "Internal ALB of the control plane"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "gateway" {
  name        = "${var.name}-gateway"
  description = "Gateway tasks"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "control_plane" {
  name        = "${var.name}-control-plane"
  description = "Control-plane tasks"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "db" {
  name        = "${var.name}-db"
  description = "RDS for PostgreSQL"
  vpc_id      = var.vpc_id
}

# --- public ALB -------------------------------------------------------------

resource "aws_vpc_security_group_ingress_rule" "public_alb_https" {
  for_each          = toset(var.gateway_ingress_cidrs)
  security_group_id = aws_security_group.public_alb.id
  description       = "HTTPS from clients"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "public_alb_to_gateway" {
  security_group_id            = aws_security_group.public_alb.id
  description                  = "To the gateway tasks"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.gateway.id
}

# --- internal ALB -----------------------------------------------------------

resource "aws_vpc_security_group_ingress_rule" "internal_alb_https" {
  for_each          = toset(var.admin_ingress_cidrs)
  security_group_id = aws_security_group.internal_alb.id
  description       = "HTTPS from admins (VPN, bastion)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "internal_alb_to_control_plane" {
  security_group_id            = aws_security_group.internal_alb.id
  description                  = "To the control-plane tasks"
  ip_protocol                  = "tcp"
  from_port                    = 8081
  to_port                      = 8081
  referenced_security_group_id = aws_security_group.control_plane.id
}

# --- gateway tasks ----------------------------------------------------------

resource "aws_vpc_security_group_ingress_rule" "gateway_from_alb" {
  security_group_id            = aws_security_group.gateway.id
  description                  = "API from the public ALB"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.public_alb.id
}

resource "aws_vpc_security_group_ingress_rule" "gateway_metrics" {
  for_each          = toset(var.metrics_ingress_cidrs)
  security_group_id = aws_security_group.gateway.id
  description       = "Prometheus scrape"
  ip_protocol       = "tcp"
  from_port         = 9090
  to_port           = 9090
  cidr_ipv4         = each.value
}

# HTTPS out: image pulls (ghcr.io), the upstream LLM, OTLP collectors. Narrow
# it with a proxy or VPC endpoints if your policy requires.
resource "aws_vpc_security_group_egress_rule" "gateway_https" {
  security_group_id = aws_security_group.gateway.id
  description       = "HTTPS out (images, upstream LLM)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "gateway_db" {
  security_group_id            = aws_security_group.gateway.id
  description                  = "PostgreSQL"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.db.id
}

# --- control-plane tasks ----------------------------------------------------

resource "aws_vpc_security_group_ingress_rule" "control_plane_from_alb" {
  security_group_id            = aws_security_group.control_plane.id
  description                  = "API and admin UI from the internal ALB"
  ip_protocol                  = "tcp"
  from_port                    = 8081
  to_port                      = 8081
  referenced_security_group_id = aws_security_group.internal_alb.id
}

resource "aws_vpc_security_group_ingress_rule" "control_plane_metrics" {
  for_each          = toset(var.metrics_ingress_cidrs)
  security_group_id = aws_security_group.control_plane.id
  description       = "Prometheus scrape"
  ip_protocol       = "tcp"
  from_port         = 9091
  to_port           = 9091
  cidr_ipv4         = each.value
}

# HTTPS out: image pulls, SSO providers (OIDC discovery and JWKS), alert
# channels (Slack, Teams, Telegram, webhooks).
resource "aws_vpc_security_group_egress_rule" "control_plane_https" {
  security_group_id = aws_security_group.control_plane.id
  description       = "HTTPS out (images, SSO, alert channels)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "control_plane_db" {
  security_group_id            = aws_security_group.control_plane.id
  description                  = "PostgreSQL"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.db.id
}

# --- database ---------------------------------------------------------------

resource "aws_vpc_security_group_ingress_rule" "db_from_gateway" {
  security_group_id            = aws_security_group.db.id
  description                  = "From the gateway tasks"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.gateway.id
}

resource "aws_vpc_security_group_ingress_rule" "db_from_control_plane" {
  security_group_id            = aws_security_group.db.id
  description                  = "From the control-plane tasks"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.control_plane.id
}

resource "aws_vpc_security_group_ingress_rule" "db_from_migration_host" {
  count                        = var.migration_host_security_group_id == "" ? 0 : 1
  security_group_id            = aws_security_group.db.id
  description                  = "From the migration host"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = var.migration_host_security_group_id
}
