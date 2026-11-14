<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Custom backend: the gateway in front of your own JSON API

> Tiếng Việt: [README.vi.md](README.vi.md).

[`sample_backend.py`](sample_backend.py) is a small search API of the kind an
organization puts in front of a model: `POST /search` takes
`{"query": "...", "filters": [...]}` and answers with results whose snippet
holds an e-mail address. [`demo.py`](demo.py) calls it through the gateway at
`/v1/backend/search/search` and checks that:

- a clean request reaches the backend **byte for byte** (`forwarded unchanged: yes`);
- the e-mail in the answer is redacted by the output guard (`redacted: ...`);
- an injection in `query` is blocked (`blocked: content_filter`) and the
  backend's request count does not move (`not reached: ...`);
- a path outside the allowed prefixes is refused (`refused path: 403 path_not_allowed`).

Both are standard-library Python 3. How custom backends work:
[docs/integrations.md](../../docs/integrations.md#custom-backend).

## Run it

With the throwaway gateway of [`examples/dev`](../README.md), which starts the
sample backend and registers it as the custom backend `search` of the
development organization:

```bash
examples/dev/start.sh
set -a; . examples/dev/.state/env; set +a
python3 examples/custom-backend/demo.py
examples/dev/stop.sh
```

Against your own gateway: start the backend somewhere the gateway can reach
(a private address needs `UPSTREAM_ALLOW_PRIVATE=true` on the gateway), add a
provider of kind **Custom backend** named `search` in the admin UI (Model
providers) with base URL `http://<backend-host>:18198`, path prefix
`/search`, method `POST`, request fields `$.query` and `$.filters[*]`, and
response field `$.results[*].snippet`, then:

```bash
python3 examples/custom-backend/sample_backend.py --host 0.0.0.0 --port 18198 &
GUARDSPEC_BASE_URL=http://localhost:8080 GUARDSPEC_API_KEY=gs_... \
GUARDSPEC_BACKEND_URL=http://127.0.0.1:18198 python3 examples/custom-backend/demo.py
```

`GUARDSPEC_BACKEND_URL` is the backend itself: the demo reads its request
count from `GET /_stats`, which the gateway does not forward.
