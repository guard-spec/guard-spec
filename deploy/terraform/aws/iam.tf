# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0

# One task execution role per service, each reading only its own secrets and
# writing only its own log group. The containers call no AWS API, so there is
# no task role.

data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

locals {
  gateway_secret_arns = concat(
    [aws_secretsmanager_secret.app_password.arn],
    aws_secretsmanager_secret.upstream_llm_key[*].arn,
  )
  control_plane_secret_arns = [
    aws_secretsmanager_secret.app_password.arn,
    aws_secretsmanager_secret.jwt_secret.arn,
    aws_secretsmanager_secret.mfa_enc_key.arn,
    aws_secretsmanager_secret.admin_password.arn,
  ]
}

data "aws_iam_policy_document" "gateway_execution" {
  statement {
    sid       = "Secrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = local.gateway_secret_arns
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.gateway.arn}:*"]
  }
  statement {
    sid       = "Images"
    actions   = ["ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = ["*"]
  }
  dynamic "statement" {
    for_each = local.kms_key_arn == null ? [] : [local.kms_key_arn]
    content {
      sid       = "Kms"
      actions   = ["kms:Decrypt"]
      resources = [statement.value]
    }
  }
}

data "aws_iam_policy_document" "control_plane_execution" {
  statement {
    sid       = "Secrets"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = local.control_plane_secret_arns
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.control_plane.arn}:*"]
  }
  statement {
    sid       = "Images"
    actions   = ["ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = ["*"]
  }
  dynamic "statement" {
    for_each = local.kms_key_arn == null ? [] : [local.kms_key_arn]
    content {
      sid       = "Kms"
      actions   = ["kms:Decrypt"]
      resources = [statement.value]
    }
  }
}

resource "aws_iam_role" "gateway_execution" {
  name               = "${var.name}-gateway-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy" "gateway_execution" {
  name   = "execution"
  role   = aws_iam_role.gateway_execution.id
  policy = data.aws_iam_policy_document.gateway_execution.json
}

resource "aws_iam_role" "control_plane_execution" {
  name               = "${var.name}-control-plane-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy" "control_plane_execution" {
  name   = "execution"
  role   = aws_iam_role.control_plane_execution.id
  policy = data.aws_iam_policy_document.control_plane_execution.json
}
