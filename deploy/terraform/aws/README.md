<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Terraform reference for AWS (ECS on Fargate)

> **Status: reference, not yet verified; community contributions welcome.**
> CI runs `terraform fmt -check`, `terraform validate` and `terraform test`
> (a plan against a mocked AWS provider). Nobody has run `terraform apply`
> with it against a real AWS account yet. If you do, please open an
> [issue](https://github.com/guard-spec/guard-spec/issues/new/choose) or a
> pull request with what worked and what did not. See
> [CONTRIBUTING.md](../../../CONTRIBUTING.md).

This is the [AWS guide](../../../docs/deploy/aws.md), option A, as
Terraform: the same architecture, security groups, task definitions and
hardening, so read the guide first. The guide explains the choices; this
file only explains how to use the module.

## Why ECS on Fargate, not EKS

- **Nothing to run below the tasks.** No cluster nodes, AMIs or Kubernetes
  upgrades to keep up with; a security team reviews task definitions, two
  ALBs and RDS.
- **No model volume.** The `guard-spec-gateway-full` image carries the L2 and
  L3 models, so every task starts with L1 + L2 + L3 and there is no EFS.
- **EKS users already have a path.** The [Helm chart](../../helm/guard-spec)
  covers Kubernetes, including EKS (guide, option B). A Terraform module for
  EKS would mostly wrap that chart.

## What it creates

| Resource | Notes |
|---|---|
| RDS for PostgreSQL 17 | Private, encrypted (`storage_encrypted`), `rds.force_ssl=1`, automated backups, deletion protection, owner password kept by RDS in Secrets Manager (`manage_master_user_password`) |
| Secrets Manager secrets | `<name>/app-password`, `jwt-secret`, `mfa-enc-key`, `admin-password`, and `upstream-llm-key` when `upstream_llm_url` is set. **Created empty**: Terraform never sees the values, so they are not in the state |
| ECS cluster, two services | Gateway (default 2 tasks) and control plane (1 task), private subnets, no public IP, read-only root filesystem, all capabilities dropped, deployment circuit breaker with rollback |
| Two ALBs | Internet-facing for the gateway (TLS 1.3/1.2 policy, idle timeout 300 s for streams, invalid headers dropped); internal for the control plane. No listener for the metrics ports |
| Security groups | As in the guide: ALB to task port only, tasks to RDS only, metrics only from `metrics_ingress_cidrs` |
| IAM | One task execution role per service, each reading only its own secrets and writing only its own log group. No task role: the containers call no AWS API |
| CloudWatch log groups | `/<name>/gateway`, `/<name>/control-plane`, retention `log_retention_days` |

It does **not** create the VPC, subnets, NAT gateway, ACM certificates, DNS
records, a WAF or a state backend. Bring your own and pass their IDs.

## Variables you will set

The full list with descriptions is in [variables.tf](variables.tf); a filled
example is [terraform.tfvars.example](terraform.tfvars.example).

| Variable | Default | What it chooses |
|---|---|---|
| `image_tag` | `0.6.0` | Release of both images |
| `gateway_image_digest`, `control_plane_image_digest` | empty | Pin by digest instead of tag (take the digest from `cosign verify`, see [docs/security](../../../docs/security/README.md#verifying-a-release)) |
| `gateway_image` | `ghcr.io/guard-spec/guard-spec-gateway-full` | `-full` has the models; the plain `guard-spec-gateway` has none and can only run `detector_layers = "l1"` here |
| `detector_layers` | `l1,l2,l3` | `DETECTOR_LAYERS`. `l1` is rules only, with fewer false positives (README, Models) |
| `l2_model`, `l3_model` | empty (the image's recommended versions) | `L2_MODEL` / `L3_MODEL` as `name@version`; must be in the image |
| `upstream_llm_url` | empty (stub answers) | `UPSTREAM_LLM_URL`; setting it adds the `upstream-llm-key` secret |
| `audit_store_content` | `false` | `AUDIT_STORE_CONTENT`. Leave off unless you need prompt text in audit rows |
| `audit_retention_days` | `90` | `AUDIT_RETENTION_DAYS` |
| `kms_key_arn` | empty | A customer managed key for RDS, Secrets Manager and the log groups (its key policy must allow CloudWatch Logs) |

## Use

You need Terraform 1.6 or newer and AWS credentials for the target account.
Configure a backend first (S3 with locking); the state holds no secret
values but does hold your network layout.

**1. First apply, no tasks.**

```bash
cd deploy/terraform/aws
cp terraform.tfvars.example terraform.tfvars   # fill in; keep both desired counts at 0
terraform init
terraform plan -out tfplan
terraform apply tfplan
```

**2. Put the secret values in** (from a shell with access to the account):

```bash
put() { aws secretsmanager put-secret-value --secret-id "guard-spec/$1" --secret-string "$2" >/dev/null; }
put app-password   "$(openssl rand -hex 32)"
put jwt-secret     "$(openssl rand -hex 32)"
put mfa-enc-key    "$(openssl rand -base64 32)"
put admin-password "$(openssl rand -hex 16)"
put upstream-llm-key '<your-upstream-key>'        # only with upstream_llm_url
```

Copy `mfa-enc-key` to an offline vault now and keep it with your RDS
snapshots: without it nobody with 2FA can log in, and there is no
re-encryption step, so never rotate it automatically.

**3. Migrations and the application password.** Terraform does not run
them. From a host inside the VPC with Docker and a checkout of the release
tag, follow
[Migrations and the application password](../../../docs/deploy/aws.md#migrations-and-the-application-password),
with `DB_HOST` and `OWNER_SECRET_ARN` from `terraform output db_address` and
`terraform output db_owner_secret_arn`. Give that host's security group in
`migration_host_security_group_id` (or add the rule yourself).

**4. Start the services.** Set `gateway_desired_count` and
`control_plane_desired_count` (for example 2 and 1) and apply again. Then
point DNS at the outputs `gateway_alb_dns_name` and
`control_plane_alb_dns_name` (a private zone for the admin host) and check:

```bash
curl -s https://<gateway-host>/readyz | jq .detector
# {"layers":["l1","l2","l3"],"degraded":false,"onnx":true,...}
```

## Upgrade

Take an RDS snapshot, run the migrations of the new tag (step 3), then set
`image_tag` (or the digests) and apply. A failing deployment rolls back to
the previous task definition by itself; a schema change does not roll back,
so restore the snapshot (with its `mfa-enc-key`) if you must go back. See
the guide's [Upgrade and rollback](../../../docs/deploy/aws.md#upgrade-and-rollback).

## Known gaps

- Not applied against a real account yet (see the status above).
- No migration task: migrations run from a host in the VPC, as in the guide.
- No metrics collector, alarms, WAF, ALB access logs or VPC endpoints. The
  guide's [Observability](../../../docs/deploy/aws.md#observability) and
  [Hardening checklist](../../../docs/deploy/aws.md#hardening-checklist) list
  what to add.
- No SSO (`OIDC_SECRET_*`), named upstream (`UPSTREAM_KEY_*`) or alert
  channel secrets. Add a secret per value and extend `gateway_secrets` /
  `control_plane_secrets` in [ecs.tf](ecs.tf) and the execution role
  policies in [iam.tf](iam.tf).

## Checks

```bash
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform test     # plans against a mocked AWS provider; no credentials needed
```
