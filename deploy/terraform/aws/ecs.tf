# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0

# ECS on Fargate: no cluster nodes to patch. The gateway uses the
# gateway-full image (models inside), so there is no shared model volume.

resource "aws_ecs_cluster" "this" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

locals {
  gateway_environment = merge(
    {
      DATABASE_URL           = local.database_url
      UPSTREAM_LLM_URL       = var.upstream_llm_url
      UPSTREAM_ALLOW_PRIVATE = "false"
      AUDIT_STORE_CONTENT    = tostring(var.audit_store_content)
      DETECTOR_LAYERS        = var.detector_layers
      DETECTOR_REQUIRE_ML    = local.require_ml
    },
    var.l2_model == "" ? {} : { L2_MODEL = var.l2_model },
    var.l3_model == "" ? {} : { L3_MODEL = var.l3_model },
    var.gateway_extra_environment,
  )

  gateway_secrets = concat(
    [{ name = "PGPASSWORD", valueFrom = aws_secretsmanager_secret.app_password.arn }],
    [for s in aws_secretsmanager_secret.upstream_llm_key : { name = "UPSTREAM_LLM_KEY", valueFrom = s.arn }],
  )

  control_plane_environment = merge(
    {
      DATABASE_URL         = local.database_url
      ADMIN_EMAIL          = var.admin_email
      PUBLIC_BASE_URL      = "https://${var.admin_host}"
      TRUSTED_PROXIES      = data.aws_vpc.this.cidr_block
      AUDIT_RETENTION_DAYS = tostring(var.audit_retention_days)
      UPSTREAM_LLM_URL     = var.upstream_llm_url
    },
    var.control_plane_extra_environment,
  )

  control_plane_secrets = [
    { name = "PGPASSWORD", valueFrom = aws_secretsmanager_secret.app_password.arn },
    { name = "JWT_SECRET", valueFrom = aws_secretsmanager_secret.jwt_secret.arn },
    { name = "MFA_ENC_KEY", valueFrom = aws_secretsmanager_secret.mfa_enc_key.arn },
    { name = "ADMIN_PASSWORD", valueFrom = aws_secretsmanager_secret.admin_password.arn },
  ]
}

resource "aws_ecs_task_definition" "gateway" {
  family                   = "${var.name}-gateway"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.gateway_cpu
  memory                   = var.gateway_memory
  execution_role_arn       = aws_iam_role.gateway_execution.arn

  runtime_platform {
    cpu_architecture        = var.cpu_architecture
    operating_system_family = "LINUX"
  }

  volume {
    name = "tmp"
  }

  container_definitions = jsonencode([{
    name                   = "gateway"
    image                  = local.gateway_image
    essential              = true
    readonlyRootFilesystem = true
    mountPoints            = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]
    portMappings = [
      { containerPort = 8080, protocol = "tcp" },
      { containerPort = 9090, protocol = "tcp" },
    ]
    environment = [for k in sort(keys(local.gateway_environment)) : { name = k, value = local.gateway_environment[k] }]
    secrets     = local.gateway_secrets
    linuxParameters = {
      capabilities = { drop = ["ALL"] }
    }
    healthCheck = {
      command     = ["CMD-SHELL", "curl -fsS http://localhost:8080/readyz || exit 1"]
      interval    = 10
      timeout     = 3
      retries     = 3
      startPeriod = 60
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.gateway.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "gateway"
      }
    }
  }])
}

resource "aws_ecs_task_definition" "control_plane" {
  family                   = "${var.name}-control-plane"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.control_plane_cpu
  memory                   = var.control_plane_memory
  execution_role_arn       = aws_iam_role.control_plane_execution.arn

  runtime_platform {
    cpu_architecture        = var.cpu_architecture
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name                   = "control-plane"
    image                  = local.control_plane_image
    essential              = true
    readonlyRootFilesystem = true
    portMappings = [
      { containerPort = 8081, protocol = "tcp" },
      { containerPort = 9091, protocol = "tcp" },
    ]
    environment = [for k in sort(keys(local.control_plane_environment)) : { name = k, value = local.control_plane_environment[k] }]
    secrets     = local.control_plane_secrets
    linuxParameters = {
      capabilities = { drop = ["ALL"] }
    }
    # The image is distroless: its health check is the binary's own
    # subcommand, not curl.
    healthCheck = {
      command     = ["CMD", "/app/service", "health"]
      interval    = 10
      timeout     = 3
      retries     = 3
      startPeriod = 30
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.control_plane.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "control-plane"
      }
    }
  }])
}

resource "aws_ecs_service" "gateway" {
  name                              = "${var.name}-gateway"
  cluster                           = aws_ecs_cluster.this.id
  task_definition                   = aws_ecs_task_definition.gateway.arn
  desired_count                     = var.gateway_desired_count
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 60
  propagate_tags                    = "SERVICE"
  enable_execute_command            = false

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.gateway.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.gateway.arn
    container_name   = "gateway"
    container_port   = 8080
  }

  depends_on = [aws_lb_listener.gateway_https]
}

# More than one control-plane task is fine: audit retention takes a Postgres
# advisory lock, and session revocations reach other replicas within 15 s.
resource "aws_ecs_service" "control_plane" {
  name                              = "${var.name}-control-plane"
  cluster                           = aws_ecs_cluster.this.id
  task_definition                   = aws_ecs_task_definition.control_plane.arn
  desired_count                     = var.control_plane_desired_count
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 30
  propagate_tags                    = "SERVICE"
  enable_execute_command            = false

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.control_plane.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.control_plane.arn
    container_name   = "control-plane"
    container_port   = 8081
  }

  depends_on = [aws_lb_listener.control_plane_https]
}
