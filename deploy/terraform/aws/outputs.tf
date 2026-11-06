# Copyright 2026 The Guard Spec Authors
# SPDX-License-Identifier: Apache-2.0

output "gateway_alb_dns_name" {
  description = "Point the gateway's host name (CNAME or alias) here."
  value       = aws_lb.gateway.dns_name
}

output "control_plane_alb_dns_name" {
  description = "Internal ALB of the admin UI; point admin_host here in a private zone."
  value       = aws_lb.control_plane.dns_name
}

output "db_address" {
  description = "RDS endpoint (DB_HOST for the migrations)."
  value       = aws_db_instance.this.address
}

output "db_owner_secret_arn" {
  description = "Secrets Manager secret RDS created for the owner (gsowner) password (OWNER_SECRET_ARN for the migrations)."
  value       = aws_db_instance.this.master_user_secret[0].secret_arn
}

output "secret_names" {
  description = "Secrets to fill before the services start (README, step 2)."
  value = merge(
    {
      app_password   = aws_secretsmanager_secret.app_password.name
      jwt_secret     = aws_secretsmanager_secret.jwt_secret.name
      mfa_enc_key    = aws_secretsmanager_secret.mfa_enc_key.name
      admin_password = aws_secretsmanager_secret.admin_password.name
    },
    { for s in aws_secretsmanager_secret.upstream_llm_key : "upstream_llm_key" => s.name },
  )
}

output "ecs_cluster_name" {
  description = "ECS cluster."
  value       = aws_ecs_cluster.this.name
}

output "gateway_image" {
  description = "Gateway image reference in the task definition."
  value       = local.gateway_image
}

output "control_plane_image" {
  description = "Control-plane image reference in the task definition."
  value       = local.control_plane_image
}
