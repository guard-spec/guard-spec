<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Deploying on your own hardware

> **Status: reference template, not yet verified by the maintainers.**
> Community-tested: not yet. If you deploy this, please open an
> [issue](https://github.com/guard-spec/guard-spec/issues/new/choose) or a pull
> request with what worked and what did not. See
> [CONTRIBUTING.md](../../CONTRIBUTING.md) and the [index](README.md).

Four setups:

1. [One VM with Docker Compose](#1-one-vm-with-docker-compose): the setup the
   README documents. Simplest; one host is a single point of failure.
2. [Kubernetes](#2-kubernetes) (vanilla) and [OpenShift](#3-openshift) with
   the Helm chart in `deploy/helm/guard-spec`.
3. [Air-gapped](#4-air-gapped-installs): no access to ghcr.io or Hugging Face.
4. [A reverse proxy for TLS](#5-reverse-proxy-and-tls) in front of any of them.

Examples use version `0.2.0` and placeholders such as `<your-db-host>`.

## 1. One VM with Docker Compose

```
                 Internet / LAN
                       |
             +---------+----------+
             |  Caddy or nginx    |  TLS, :443
             +---+------------+---+
                 |            |  (admin site: internal clients only)
       127.0.0.1:8080   127.0.0.1:18081
          gateway        control-plane  -- /ui/
                 \            /
                  +----------+
                  | postgres |  volume pgdata
                  +----------+
       ./models (read-only in the gateway, filled by models-init)
```

### Prerequisites

- Linux host with Docker Engine and Compose v2, `curl`, `jq`, `openssl`.
- Starting point for the host: measure under your traffic. In a local check
  the `gateway-full` container used about 900 MiB of memory right after
  start with L1 + L2 + L3 loaded. Plan for at least 2 GiB for the gateway
  (the chart's default limit), plus Postgres. L1 only needs much less.
- About 300 MB of disk for the models and space for the audit table.

### Steps

```bash
git clone --branch v0.2.0 https://github.com/guard-spec/guard-spec.git
cd guard-spec
scripts/quickstart.sh
```

`scripts/quickstart.sh` writes `.env` with random secrets (mode 600), starts
`docker-compose.yml` alone (never the dev override), pulls the models and
waits for `/readyz`. To fill `.env` yourself instead: `cp .env.example .env`,
generate each secret (`openssl rand -hex 32`; `MFA_ENC_KEY` with
`openssl rand -base64 32`), then `docker compose -f docker-compose.yml up -d`.

Always pass `-f docker-compose.yml`. A plain `docker compose up` also loads
`docker-compose.override.yml`, which sets `GUARD_ENV=dev` and well-known
credentials.

### Production notes for compose

Edit `.env`, then `docker compose -f docker-compose.yml up -d` again.

| Setting | Compose default | For production |
|---|---|---|
| `UPSTREAM_KEY_ORGS` | `UPSTREAM_KEY_MAIN=*` | List the org ids that may use each key, if users you do not trust can create organizations |
| `UPSTREAM_ALLOW_PRIVATE` | `true` (for Ollama on the host) | `false`, unless your upstream is on a private address and org admins are trusted |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Empty. The UI at `/ui/` is same-origin and needs no CORS |
| `ADMIN_EMAIL` | `admin@example.com` in `.env.example` | A real mailbox |
| `PUBLIC_BASE_URL` | empty | `https://<admin-host>`, needed for SSO |
| `TRUSTED_PROXIES` | empty | The address range your reverse proxy connects from (below) |
| `GATEWAY_PORT` and the other ports | published on all interfaces | Bind to loopback behind a proxy (below) |

**Ports.** Compose publishes 8080, 9090, 18081 and 9091 on every interface,
and Docker's published ports bypass host firewalls such as `ufw`. Behind a
reverse proxy on the same host, bind them to loopback. The port variables are
used as `"${GATEWAY_PORT:-8080}:8080"`, so a host address can go in front:

```bash
# .env
GATEWAY_PORT=127.0.0.1:8080
METRICS_PORT=127.0.0.1:9090
CONTROL_PLANE_PORT=127.0.0.1:18081
CONTROL_PLANE_METRICS_PORT=127.0.0.1:9091
```

**`TRUSTED_PROXIES`.** A proxy on the host reaches the control plane through
the compose network, so the control plane sees an address of that network.
Find its subnet and set it:

```bash
docker network inspect guard-spec_default --format '{{(index .IPAM.Config 0).Subnet}}'
# .env: TRUSTED_PROXIES=<that subnet>
```

Without it, the control plane ignores `X-Forwarded-For` and every client
looks like the proxy (one rate-limit bucket for logins, one address in the
activity log).

### Backups

Back up the database and `.env` together; `MFA_ENC_KEY` in `.env` must match
the database it encrypts.

```bash
set -a; . ./.env; set +a
docker compose -f docker-compose.yml exec -T postgres \
  pg_dump -U ps -Fc "${POSTGRES_DB:-guardspec}" > guardspec-$(date +%F).dump
cp .env env-$(date +%F).backup    # store it as a secret, not next to the dump
```

### Upgrade and rollback

```bash
docker compose -f docker-compose.yml exec -T postgres pg_dump -U ps -Fc guardspec > pre-upgrade.dump
git fetch --tags && git checkout v<new-version>    # new migrations/ and docker-compose.yml
# .env: GUARDSPEC_VERSION=<new-version>
docker compose -f docker-compose.yml pull
docker compose -f docker-compose.yml up -d         # migrate and db-roles run before the services
curl -s localhost:8080/readyz | jq .detector
```

Read the [CHANGELOG](../../CHANGELOG.md) first: before 1.0, minor versions can
change the schema. To roll back, go back to the old tag and
`GUARDSPEC_VERSION`, and restore `pre-upgrade.dump` if the new version
migrated the schema. The `*.down.sql` files exist, but a restore is the
tested path for data you care about. Model rollback is separate and covered
in [docs/models.md](../models.md#rolling-back).

## 2. Kubernetes

The chart deploys the gateway and the control plane against an external
Postgres. It does not run migrations, and it has no Ingress, autoscaling or
PodDisruptionBudget yet. The steps below fill those gaps with plain
manifests. Release name `gs` gives the Services `gs-guard-spec-gateway` and
`gs-guard-spec-control-plane`.

```
   clients --> Ingress (TLS) --> Service gs-guard-spec-gateway:8080 --> gateway pods (2)
                                                                           |  /models (PVC, read-only)
   admins (VPN) --> internal Ingress or port-forward
                     --> Service gs-guard-spec-control-plane:8081 --> control-plane pod
                                                                           |
                                                    external PostgreSQL 17 <+
```

### Prerequisites

- Kubernetes 1.27 or newer (an assumption: the chart uses only stable APIs),
  Helm 3 or 4, `kubectl`.
- PostgreSQL 17 reachable from the cluster, with an owner role that can
  create roles and the `pgcrypto` and `pg_trgm` extensions. Migration 004
  runs `CREATE ROLE guardspec_app`, and roles are cluster-wide in Postgres:
  use a server where that role does not exist yet, or one database server
  per installation.
- A checkout of the release tag: `git clone --branch v0.2.0 https://github.com/guard-spec/guard-spec.git`.
  See [The Helm chart on `main`](README.md#the-helm-chart-on-main).

### Step 1: namespace and secrets

```bash
kubectl create namespace guard-spec
kubectl config set-context --current --namespace guard-spec

kubectl create secret generic guard-spec-secrets \
  --from-literal=POSTGRES_PASSWORD='<owner-password>' \
  --from-literal=GUARDSPEC_APP_PASSWORD="$(openssl rand -hex 32)" \
  --from-literal=JWT_SECRET="$(openssl rand -hex 32)" \
  --from-literal=ADMIN_PASSWORD="$(openssl rand -hex 16)" \
  --from-literal=MFA_ENC_KEY="$(openssl rand -base64 32)"

# Gateway-only secrets (the upstream's key), passed with gateway.extraEnvFrom.
kubectl create secret generic guard-spec-gateway-extra \
  --from-literal=UPSTREAM_LLM_KEY='<your-upstream-key>'
```

**Back up `MFA_ENC_KEY` now**, outside the cluster, next to your database
backups: `kubectl get secret guard-spec-secrets -o jsonpath='{.data.MFA_ENC_KEY}' | base64 -d`.
Read `ADMIN_PASSWORD` the same way for the first login.

### Step 2: migrations (no chart job yet)

Run `migrate` as a one-off Job, with `migrations/` from the release tag in a
ConfigMap (about 160 KB, under the 1 MiB ConfigMap limit). The password comes
from `PGPASSWORD`, as in compose, so the URL carries none.

```bash
kubectl create configmap guard-spec-migrations-0-1-1 --from-file=migrations/
kubectl apply -f - <<'EOF'
# Template: adjust host, owner user and sslmode.
apiVersion: batch/v1
kind: Job
metadata:
  name: guard-spec-migrate-0-1-1
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: migrate
          image: migrate/migrate:v4.20.1
          args:
            - -path=/migrations
            - -database=postgres://<owner-user>@<your-db-host>:5432/guardspec?sslmode=require
            - up
          env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef: {name: guard-spec-secrets, key: POSTGRES_PASSWORD}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          volumeMounts:
            - {name: migrations, mountPath: /migrations, readOnly: true}
      volumes:
        - name: migrations
          configMap: {name: guard-spec-migrations-0-1-1}
EOF
kubectl wait --for=condition=complete job/guard-spec-migrate-0-1-1 --timeout=5m
kubectl logs job/guard-spec-migrate-0-1-1
```

The `guardspec_app` password is set by the chart's `dbRoles` hook in step 4
(`dbRoles.enabled=true`). Without it, run
`GUARDSPEC_APP_PASSWORD=... sh deploy/postgres/set-app-password.sh` with the
owner's credentials in `PGHOST`, `PGUSER`, `PGDATABASE` and `PGPASSWORD`.

### Step 3: models

The gateway reads the models from a PVC mounted read-only at `/models`. The
chart's PVC is ReadWriteOnce by default, so with two gateway replicas on
different nodes only one can mount it. Options:

| Option | How |
|---|---|
| A ReadWriteMany storage class (NFS, CephFS, ...) | Create the PVC yourself (below) and pass `models.existingClaim` |
| ReadWriteOnce | `gateway.replicaCount=1`, or pin the replicas to one node with `gateway.affinity` |
| No volume | `gateway-full`, see [gateway-full with the Helm chart](#gateway-full-with-the-helm-chart) |

Create and fill the PVC before installing, so the gateway starts with its
models:

```bash
kubectl apply -f - <<'EOF'
# Template: pick a storage class that offers ReadWriteMany.
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: guard-spec-models
spec:
  accessModes: [ReadWriteMany]
  storageClassName: <your-rwx-storage-class>
  resources:
    requests: {storage: 5Gi}
---
apiVersion: batch/v1
kind: Job
metadata:
  name: guard-spec-models-pull-0-1-1
spec:
  backoffLimit: 2
  template:
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: models
          image: ghcr.io/guard-spec/guard-spec-gateway:0.2.0
          command: ["./models", "pull", "-manifest", "manifest.yaml", "-dir", "/models/cache"]
          env:
            - {name: MODELS_MIRROR, value: ""}   # optional internal mirror
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          volumeMounts:
            - {name: models, mountPath: /models}
            - {name: tmp, mountPath: /tmp}
      volumes:
        - name: models
          persistentVolumeClaim: {claimName: guard-spec-models}
        - name: tmp
          emptyDir: {}
EOF
kubectl wait --for=condition=complete job/guard-spec-models-pull-0-1-1 --timeout=15m
```

The same command with a model reference (`... /models/cache guardspec-classifier@<version>`)
installs another version for a rollback ([docs/models.md](../models.md)).

### Step 4: install the chart

```bash
cat > values-prod.yaml <<'EOF'
# Template. See deploy/helm/guard-spec/values.yaml for every key.
externalDatabase:
  url: postgres://guardspec_app@<your-db-host>:5432/guardspec?sslmode=require
  host: <your-db-host>
  ownerUser: <owner-user>
  sslmode: require
dbRoles:
  enabled: true
models:
  existingClaim: guard-spec-models
gateway:
  replicaCount: 2
  # The default resources (request 500m CPU / 1Gi, limit 2Gi) fit
  # L1 + L2 + L3; measure under your traffic and adjust gateway.resources.
  env:
    UPSTREAM_LLM_URL: <your-upstream-url>   # e.g. https://api.openai.com/v1
    UPSTREAM_ALLOW_PRIVATE: "false"
  extraEnvFrom:
    - secretRef: {name: guard-spec-gateway-extra}
controlPlane:
  adminEmail: <admin-email>
  env:
    PUBLIC_BASE_URL: https://<admin-host>
    TRUSTED_PROXIES: <ingress-controller-pod-cidr>
EOF

helm install gs deploy/helm/guard-spec -f values-prod.yaml
kubectl rollout status deploy/gs-guard-spec-gateway
kubectl port-forward svc/gs-guard-spec-gateway 8080:8080 &
curl -s localhost:8080/readyz | jq .detector    # expect "layers":["l1","l2","l3"], "degraded":false
```

### Step 5: Ingress, PodDisruptionBudget, NetworkPolicy

Not in the chart yet. Templates for ingress-nginx; adapt to your controller.

```yaml
# Template: public Ingress for the gateway only.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: guard-spec-gateway
  annotations:
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"   # long or streamed answers
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-body-size: "8m"
spec:
  ingressClassName: nginx
  tls:
    - hosts: [<gateway-host>]
      secretName: guard-spec-gateway-tls
  rules:
    - host: <gateway-host>
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service: {name: gs-guard-spec-gateway, port: {number: 8080}}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: guard-spec-gateway
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/instance: gs
      app.kubernetes.io/component: gateway
---
# Only the ingress controller may reach the gateway's API port; nothing
# outside the namespace reaches the control plane. Add rules for in-cluster
# clients of the gateway and for your Prometheus (ports 9090 and 9091).
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: guard-spec-ingress
spec:
  podSelector:
    matchLabels: {app.kubernetes.io/instance: gs}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels: {kubernetes.io/metadata.name: ingress-nginx}
      ports:
        - {port: 8080, protocol: TCP}
```

Reach the control plane with `kubectl port-forward svc/gs-guard-spec-control-plane 8081:8081`
(admin UI at `http://localhost:8081/ui/`), or with a second Ingress on an
internal-only controller. Do not publish it on the public Ingress.

There is no HorizontalPodAutoscaler in the chart. A plain
`autoscaling/v2` HPA on `deploy/gs-guard-spec-gateway` works like for any
Deployment; remember that rate limits are per replica, so scaling out raises
the effective limit.

### gateway-full with the Helm chart

`guard-spec-gateway-full` has the models inside the image, so it needs no
PVC and no models Job (skip step 3). Without a models claim the chart mounts
nothing at `/models`, and the image's models stay visible:

```bash
helm install gs deploy/helm/guard-spec -f values-prod.yaml \
  --set models.existingClaim= --set models.persistence.enabled=false \
  --set gateway.image.repository=ghcr.io/guard-spec/guard-spec-gateway-full
```

The image sets `DETECTOR_REQUIRE_ML=true`: if a volume is mounted over
`/models` anyway, it refuses to start rather than run on L1 only.

### Upgrade and rollback

1. Read the CHANGELOG. Snapshot or `pg_dump` the database.
2. Check out the new tag, create a ConfigMap and Job with the new
   `migrations/` (new names, such as `guard-spec-migrate-0-2-0`), wait for
   completion.
3. `helm upgrade gs deploy/helm/guard-spec -f values-prod.yaml`. The
   `dbRoles` hook runs again (`pre-upgrade`).
4. Check `/readyz`.

`helm rollback gs` restores the previous images; it does not undo
migrations. Restore the database snapshot if the new version changed the
schema.

## 3. OpenShift

Everything in [Kubernetes](#2-kubernetes) applies, with these changes.

**Random UIDs.** The chart sets `runAsUser: 65532`, `runAsGroup` and
`fsGroup` in `podSecurityContext`, which the `restricted-v2` SCC rejects
unless they are in the namespace's range. Remove them and let OpenShift pick
the UID:

```bash
helm install gs deploy/helm/guard-spec -f values-prod.yaml \
  --set podSecurityContext.runAsUser=null \
  --set podSecurityContext.runAsGroup=null \
  --set podSecurityContext.fsGroup=null
```

The images do not depend on a fixed UID: their files are world-readable,
nothing is written outside `/tmp` (an `emptyDir` in the chart), and the
`gateway-full` models are `a=rX`. In a local check,
`guard-spec-gateway-full:0.1.1` and `guard-spec-control-plane:0.1.1` started
and loaded L1 + L2 + L3 as UID 1000770000, group 0, with a read-only root
filesystem. Not yet run on an OpenShift cluster.

**dbRoles.** The job's pod securityContext comes from
`dbRoles.podSecurityContext` (`runAsNonRoot` and RuntimeDefault seccomp). The
chart adds `runAsUser: 70` only when the cluster does not serve
`security.openshift.io/v1`, so on OpenShift the SCC picks the UID and
`dbRoles.enabled=true` works as in step 4. With `helm template` (GitOps),
pass `--api-versions security.openshift.io/v1`. Remove `runAsUser`,
`runAsGroup` and `fsGroup` from the migration and model Jobs above as well.

**Routes instead of Ingress.**

```bash
oc create route edge guard-spec-gateway --service=gs-guard-spec-gateway \
  --hostname=<gateway-host> --port=http
oc annotate route guard-spec-gateway haproxy.router.openshift.io/timeout=300s
```

Do not create a route for the control plane unless it is on an internal
router shard.

## 4. Air-gapped installs

You need, inside the network: the images, the models, and the repository at
the release tag (for `migrations/`, `docker-compose.yml` and the chart).

### Images

| Image | Needed for |
|---|---|
| `ghcr.io/guard-spec/guard-spec-gateway:0.2.0` | gateway, `models-init`, `models-pull` |
| `ghcr.io/guard-spec/guard-spec-gateway-full:0.2.0` | gateway with models inside (instead of the one above) |
| `ghcr.io/guard-spec/guard-spec-control-plane:0.2.0` | control plane |
| `migrate/migrate:v4.20.1` | migrations |
| `postgres:17.11-alpine` | Postgres in compose, `db-roles`, the chart's `dbRoles` job |

Copy them to an internal registry with all platforms, for example with
`crane copy` or `skopeo copy --all`, and verify the signatures before you do
([SECURITY.md](../../SECURITY.md#verifying-releases)):

```bash
crane copy ghcr.io/guard-spec/guard-spec-gateway-full:0.2.0 <your-registry>/guard-spec/guard-spec-gateway-full:0.2.0
```

With compose, point the services at the mirror with a second file instead of
editing `docker-compose.yml`:

```yaml
# docker-compose.airgap.yml (template)
services:
  gateway:       {image: <your-registry>/guard-spec/guard-spec-gateway:0.2.0}
  models-init:   {image: <your-registry>/guard-spec/guard-spec-gateway:0.2.0}
  models-pull:   {image: <your-registry>/guard-spec/guard-spec-gateway:0.2.0}
  control-plane: {image: <your-registry>/guard-spec/guard-spec-control-plane:0.2.0}
  migrate:       {image: <your-registry>/migrate/migrate:v4.20.1}
  db-roles:      {image: <your-registry>/library/postgres:17.11-alpine}
  postgres:      {image: <your-registry>/library/postgres:17.11-alpine}
```

```bash
docker compose -f docker-compose.yml -f docker-compose.airgap.yml up -d
```

With Helm: `gateway.image.repository`, `controlPlane.image.repository`,
`dbRoles.image.repository` and `imagePullSecrets`.

### Models

Three ways, from simplest:

1. **`gateway-full`.** The models are in the image; nothing to download. With
   compose, the `./models:/models:ro` mount in `docker-compose.yml` hides
   them, so use the plain gateway image there (option 2), or remove the mount
   in your override with `volumes: !reset []` (needs a Compose version that
   supports `!reset`). With Helm, see
   [gateway-full with the Helm chart](#gateway-full-with-the-helm-chart).
2. **Copy `models/cache`.** On a connected machine:

   ```bash
   docker run --rm -v "$PWD/models:/models" --entrypoint ./models \
     ghcr.io/guard-spec/guard-spec-gateway:0.2.0 pull -manifest manifest.yaml -dir /models/cache
   tar czf guard-spec-models-0.1.0.tgz models/cache
   ```

   On the target, unpack into the checkout and verify:

   ```bash
   tar xzf guard-spec-models-0.1.0.tgz
   docker run --rm -v "$PWD/models:/models:ro" --entrypoint ./models \
     <your-registry>/guard-spec/guard-spec-gateway:0.2.0 verify -manifest manifest.yaml -dir /models/cache
   ```

   `models-init` then finds the files present and verified and downloads
   nothing.
3. **An internal mirror.** Serve a copy of `models/cache` from any static file
   server; `MODELS_MIRROR=<url>` makes `models pull` try
   `<url>/<name>/<version>/<file>` first ([docs/models.md](../models.md#pulling)).
   Every file is still checked against the SHA-256 in the manifest.

Set `DETECTOR_REQUIRE_ML=true` so that a missing model stops the stack instead
of falling back to L1 without anyone noticing.

## 5. Reverse proxy and TLS

The services speak plain HTTP. Put a proxy in front that terminates TLS,
passes streamed answers through without buffering, and keeps the control
plane off the public side.

### Caddy

```caddyfile
# Template. Caddy gets certificates automatically for public names.
<gateway-host> {
	reverse_proxy 127.0.0.1:8080 {
		flush_interval -1            # stream answers as they arrive
		transport http {
			read_timeout 5m          # matches UPSTREAM_LLM_TIMEOUT
		}
	}
}

<admin-host> {
	@outside not remote_ip 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
	respond @outside 403
	reverse_proxy 127.0.0.1:18081
}
```

### nginx

```nginx
# Template.
server {
    listen 443 ssl;
    server_name <gateway-host>;
    ssl_certificate     /etc/ssl/<gateway-host>.crt;
    ssl_certificate_key /etc/ssl/<gateway-host>.key;
    client_max_body_size 8m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;           # streamed answers
        proxy_read_timeout 300s;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 443 ssl;
    server_name <admin-host>;
    ssl_certificate     /etc/ssl/<admin-host>.crt;
    ssl_certificate_key /etc/ssl/<admin-host>.key;
    allow 10.0.0.0/8;
    deny all;

    location / {
        proxy_pass http://127.0.0.1:18081;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Then set `PUBLIC_BASE_URL=https://<admin-host>` and `TRUSTED_PROXIES` on the
control plane. The gateway does not read `X-Forwarded-For`; its rate limits
are per API key.

## Hardening checklist

None of these cost money.

- [ ] `GUARD_ENV` is empty; the dev override is never loaded.
- [ ] `MFA_ENC_KEY` is set and backed up with the database backups.
- [ ] Control plane and both metrics ports are not reachable from the
      internet.
- [ ] `UPSTREAM_KEY_ORGS` lists org ids, not `*`, if untrusted users can
      create organizations; `UPSTREAM_ALLOW_PRIVATE=false` unless needed.
- [ ] Postgres is not published; connections use TLS
      (`sslmode=require` or stronger) when it is on another host.
- [ ] `DETECTOR_REQUIRE_ML=true` if you rely on the model layers.
- [ ] The first admin changed the bootstrap password, and 2FA is required for
      admins (`PUT /v1/organizations/:orgId/security`).
- [ ] `AUDIT_STORE_CONTENT` stays `false` unless you need prompt content in
      the audit log; `AUDIT_RETENTION_DAYS` matches your policy.
- [ ] Image signatures are verified before mirroring
      ([SECURITY.md](../../SECURITY.md#verifying-releases)).
- [ ] A WAF or rate limiter in front of the gateway for volume abuse.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| A service exits at start naming a variable | A secret is missing, a default or too short. Set the named variable |
| `db connect` in the gateway log and exit | Wrong `DATABASE_URL`, `PGPASSWORD` not set, or `guardspec_app` has no password yet (run `set-app-password.sh` after migrating) |
| `password authentication failed for user "guardspec_app"` | `GUARDSPEC_APP_PASSWORD` changed but was not applied: run `db-roles` / `set-app-password.sh` again |
| `/readyz` shows `"layers":["l1"]`, `"degraded":true` | No models at `/models`. See `detector.problems`; fill the volume and restart |
| `gateway-full` refuses to start | A volume is mounted over `/models`; with the chart, set `models.persistence.enabled=false` and leave `models.existingClaim` empty |
| Migration `004` fails with "role already exists" | `guardspec_app` exists on this Postgres server from another database |
| Streams stop after 30 to 60 seconds | Proxy or load balancer read timeout; raise it and turn off buffering |
| 2FA users cannot log in after a restore | `MFA_ENC_KEY` does not match the restored database |
