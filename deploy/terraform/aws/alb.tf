# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0

# Two load balancers: an internet-facing one for the gateway API and an
# internal one for the control plane (admin UI and API). Neither forwards
# the metrics ports. HTTPS only; add an HTTP listener that only redirects if
# you need one.

locals {
  tls_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

resource "aws_lb" "gateway" {
  name                       = "${var.name}-gw"
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = var.public_subnet_ids
  security_groups            = [aws_security_group.public_alb.id]
  drop_invalid_header_fields = true
  # Streamed answers: the default (60 s) cuts long silences.
  idle_timeout = 300
}

resource "aws_lb_target_group" "gateway" {
  name                 = "${var.name}-gw"
  port                 = 8080
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 30

  # /readyz answers 503 when a layer the configuration requires is missing.
  health_check {
    path                = "/readyz"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "gateway_https" {
  load_balancer_arn = aws_lb.gateway.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = local.tls_policy
  certificate_arn   = var.gateway_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway.arn
  }
}

resource "aws_lb" "control_plane" {
  name                       = "${var.name}-cp"
  load_balancer_type         = "application"
  internal                   = true
  subnets                    = var.private_subnet_ids
  security_groups            = [aws_security_group.internal_alb.id]
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "control_plane" {
  name                 = "${var.name}-cp"
  port                 = 8081
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 30

  health_check {
    path                = "/health"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "control_plane_https" {
  load_balancer_arn = aws_lb.control_plane.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = local.tls_policy
  certificate_arn   = var.admin_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.control_plane.arn
  }
}
