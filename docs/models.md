<!-- Copyright 2026 The Guard Spec Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Models: versions, pulling, pinning and rollback

The gateway's detector has three layers. L1 (rules) is built into the
binary. L2 (our classifier, `guardspec-classifier`) and L3 (the
`multilingual-e5-small` embedder) are ONNX models that are never baked into
an image or committed to git: they are downloaded, verified and mounted at
`/models`.

[`models/manifest.yaml`](../models/manifest.yaml) lists every model version
that can be pulled. The same file is built into the gateway and the `models`
tool, so the binary always knows its recommended models.

| Model | Version | Layer | Recommended | Source |
|---|---|---|---|---|
| `guardspec-classifier` | `v3b` | L2 | yes | Hugging Face (not published yet), then the GitHub Release `model-guardspec-classifier-v3b` |
| `guardspec-classifier` | `v4` | L2 | no: candidate, [compare in shadow mode](#guardspec-classifier-v4-candidate) | the GitHub Release `model-guardspec-classifier-v4` (once the owner publishes it) |
| `multilingual-e5-small` | `614241f` | L3 | yes | Hugging Face `intfloat/multilingual-e5-small` |
| `protectai-deberta-v3-small-pi-v2` | `d7c8842` | baseline | optional, gated | Hugging Face |
| `protectai-deberta-v3-base-pi-v2` | `90c9989` | baseline | optional | Hugging Face |

`models list --available` prints the current list. Version names of models
we did not train are the first 7 characters of their pinned Hugging Face
revision.

## Layout

A version is installed in `<dir>/<name>/<version>/`; with compose,
`<dir>` is `./models/cache`:

```
models/cache/
  guardspec-classifier/v3b/     model_int8.onnx tokenizer.json config.json thresholds.json calibration.json
  multilingual-e5-small/614241f/  model.onnx tokenizer.json config.json
```

Several versions of one model can sit side by side; that is what makes a
rollback a restart.

## Pulling

```bash
# Docker: models-init does this before the gateway starts, on every `up`
docker compose --profile models run --rm models-pull                           # recommended versions
docker compose --profile models run --rm models-pull guardspec-classifier@v3b  # one version

# Without Docker
go run ./cmd/models pull                              # recommended version of every non-optional model
go run ./cmd/models pull guardspec-classifier@v3b     # one version
go run ./cmd/models pull -models a,b@v1               # the older flag form still works
go run ./cmd/models list                              # what is installed
go run ./cmd/models list --available                  # what the manifest offers
go run ./cmd/models verify                            # re-check the SHA-256 of installed files
```

What `pull` guarantees:

- **Verified.** Every file is checked against the size and SHA-256 pinned in
  the manifest, whichever source it came from. A mismatch is refused.
- **Atomic.** A version is assembled in a hidden temporary directory next to
  it and renamed into place only when every file verified. A failed or
  interrupted pull leaves the previous state as it was.
- **Idempotent.** When a version is present and verifies, nothing is
  downloaded. Files from the layout before versions
  (`models/cache/multilingual-e5-small/model.onnx`) are reused, not
  downloaded again.
- **Fallback.** Sources are tried in order: `-mirror` / `MODELS_MIRROR`
  when set, Hugging Face at the pinned commit, then the manifest's `mirrors`
  (our GitHub Release assets). While a model is not on Hugging Face its
  revision is the all-zero placeholder and Hugging Face is skipped.
  `HF_TOKEN` is only ever sent to Hugging Face.

`MODELS_MIRROR` is a base URL serving `<mirror>/<name>/<version>/<file>`, for
an internal mirror or a proxy-restricted network. Any static file server
over a copy of `models/cache` works, for example
`python3 -m http.server -d models/cache 8000` and
`MODELS_MIRROR=http://host.docker.internal:8000`.

## Choosing a version in the gateway

The gateway resolves each model layer in this order:

1. `L2_MODEL_DIR` / `L3_MODEL_DIR`: that directory, as is (the older
   variables; they win when set);
2. `L2_MODEL` / `L3_MODEL` = `name@version`: `$MODEL_DIR/cache/<name>/<version>`.
   A bare name means its recommended version;
3. nothing set: the manifest's recommended model, when installed;
4. the directories from before versions: `$MODEL_DIR/local/guardspec-classifier-v3b`
   (then `-v2`, `-v1`, `-v0`) for L2 and `$MODEL_DIR/cache/multilingual-e5-small`
   for L3.

An explicit choice (1 or 2) that is not installed is not replaced by another
model: the layer stays off and `/readyz` says why. `MODEL_DIR` is `/models`
in the image and `./models` otherwise.

`GET /readyz` shows what loaded:

```json
{"detector":{"layers":["l1","l2","l3"],"degraded":false,"onnx":true,"fusion":"logreg","l2_model":"guardspec-classifier-v3b"},"status":"ready","version":"0.1.0"}
```

## Pinning

- **Images** are pinned by `GUARDSPEC_VERSION` (default `0.1.0`). Each image
  contains the manifest of its release, so the models it recommends are
  pinned with it.
- **Models** are pinned by `L2_MODEL=guardspec-classifier@v3b` (and
  `L3_MODEL`). Set them in `.env` to keep a version across image upgrades
  that recommend a newer one; models-init still pulls the new recommended
  version, but the gateway keeps loading the pinned one.
- **Files** are pinned by SHA-256 in the manifest, and upstream models by
  their Hugging Face commit.

## Rolling back

1. Make sure the older version is installed:
   `docker compose --profile models run --rm models-pull guardspec-classifier@<old>`
   (`models list` shows what is there).
2. Set `L2_MODEL=guardspec-classifier@<old>` in `.env`.
3. Restart the gateway: `docker compose up -d gateway`. Or, without a
   restart, `POST /admin/models/reload` with
   `{"l2_model":"guardspec-classifier@<old>"}` (see below), and keep step 2 for
   the next restart.
4. Check `/readyz` (`l2_model`, `models.l2_model`) and the log line
   `L2 classifier loaded`.

Undo by removing `L2_MODEL` and restarting. Calibration travels with the
model (`calibration.json` in the version directory), so the fusion weights
always match the classifier that is loaded.

## Comparing a candidate first (shadow mode)

Before switching, run the candidate next to the active classifier:

```bash
# .env
SHADOW_L2_MODEL=guardspec-classifier@<candidate>   # pulled first
SHADOW_SAMPLE=1                                    # share of requests compared
```

It scores the same traffic and records what it would have decided in
`shadow_results`; it never changes a decision and runs off the response
path. The admin UI's **Models** page shows the agreement rate, the requests
where the candidate would block or allow differently, and the score
distributions. README, [Shadow mode and model reload](../README.md#shadow-mode-and-model-reload),
has the details.

### guardspec-classifier v4 (candidate)

`guardspec-classifier@v4` is listed in the manifest but is **not** the
recommended version: v3b stays the default until v4 has been compared in
shadow mode. v4 is v3b's architecture and recipe trained on more Vietnamese
data (owner-written teencode, no-diacritics and banking rows, and new hard
negatives); it blocks fewer benign Vietnamese messages. The comparison with
v3b is below ([v3b vs v4](#v3b-vs-v4)) and in
[train/MODEL_CARD.md](../train/MODEL_CARD.md) ("v4").

```bash
# 1. Install it next to v3b (files checked against the manifest's SHA-256).
#    It comes from the Hugging Face branch v4 at the pinned commit, with the
#    GitHub release model-guardspec-classifier-v4 as the mirror.
docker compose --profile models run --rm models-pull guardspec-classifier@v4
# 2. .env: keep v3b deciding, let v4 score the same traffic.
L2_MODEL=guardspec-classifier@v3b
SHADOW_L2_MODEL=guardspec-classifier@v4
SHADOW_SAMPLE=1
# 3. Restart the gateway (or POST /admin/models/reload), then watch the
#    Models page: agreement, requests v4 would block that v3b allows (and the
#    reverse), score distributions.
```

With a local copy of the files instead (for example before the release
exists), set `SHADOW_L2_MODEL_DIR=/path/to/guardspec-classifier-v4`; the
directory must hold `model_int8.onnx`, `tokenizer.json`, `config.json`,
`thresholds.json` and `calibration.json` (v4's fusion calibration travels in
that file). Once the comparison is satisfactory, switching is
`L2_MODEL=guardspec-classifier@v4` and a reload; rolling back is the reverse.

#### v3b vs v4

Gateway scores (fused L1+L2+L3, block at 0.85). The eval set was measured
once for v4; the owner hold-out is owner-written data that neither model
trained on.

| | v3b | v4 |
|---|---|---|
| eval ROC AUC | 0.9865 | 0.9853 |
| eval TPR / FPR at 0.85 | 0.939 / 1.39% (14 of 1,005) | 0.932 / 1.19% (12) |
| eval EN FPR / VI FPR | 1.65% / 1.25% | 1.10% / 1.25% |
| eval VI teencode / no-diacritics FPR | 3.5% (5 of 143) / 0.4% (1 of 236) | 1.4% (2) / 1.7% (4) |
| owner hold-out FPR / TPR | 1.6% (3 of 184) / 0.714 | 0.5% (1) / 0.688 |
| owner teencode/no-diacritics: FPR / TPR / ROC AUC | 4.2% (2 of 48) / 0.417 / 0.763 | 2.1% (1) / 0.472 / 0.878 |
| Vietnamese benign false positives (owner hold-out, `val_v4_holdout`, the 4 reported sentences) | 11 of 275 | 4 of 275 |
| the 4 reported sentences blocked | 4 | 1 |

v4 blocks fewer benign Vietnamese messages but catches slightly fewer
attacks (eval: 7 fewer of 1,171; lower on Vietnamese data exfiltration and
tool poisoning and on English leet). It did not pass the pre-registered
decision rule, which is why it is a candidate for shadow mode and not the
default. [train/MODEL_CARD.md](../train/MODEL_CARD.md) ("v4") has every
table.

## Reloading without a restart

`kill -HUP` the gateway, or `POST /admin/models/reload` with
`GATEWAY_ADMIN_TOKEN`, loads the classifier again (or another version), checks
every file against the manifest's SHA-256, and swaps it in without dropping a
request. A failure keeps the running model. Versions that the built-in
manifest does not list (a model of your own) need a manifest file that lists
them, named by `MODELS_MANIFEST`, with the same format as
`models/manifest.yaml`.

## Air-gapped installs

Two options:

- **The `gateway-full` image**, which contains the recommended models of its
  release (built from `build/gateway-full.Dockerfile`). Move it with
  `docker save` / `docker load`. It needs no models-init download; set
  `MODEL_DIR` as its documentation says.
- **A copy of `models/cache`.** On a connected machine run `models pull`,
  copy the directory, and on the target run `models verify` before
  starting. models-init then finds the files present and verified and does
  nothing. Alternatively, serve the copy from an internal file server and set
  `MODELS_MIRROR`.

Without network and without models, models-init warns and the gateway runs
on L1 only (`/readyz` lists the missing layers), unless
`DETECTOR_REQUIRE_ML=true`, which stops the stack instead.

## False positives: fix them now with exemplars

A new model version takes a training run, an eval and a release. The fix
for a false positive today is the **Exemplars** page of the admin UI
(`/ui/`, or `POST /v1/organizations/:orgId/exemplars`):

- add the wrongly blocked text as an **allow** exemplar: it lowers the L3
  score of similar requests for that organization; a **block** exemplar does
  the opposite and puts a floor under the fused score;
- check the request's `scores` in the request log first: an allow exemplar
  acts on L3 only, so when L2 alone drives the score it lowers the fused
  score only partly. Report such texts (without customer data) so that the
  next model version learns from them;
- exemplars need the L3 model and take effect within about 5 seconds, with
  no restart.

## Releasing a new model version

For maintainers. The example releases `guardspec-classifier` `v4`.

1. **Train** with `train/` (see [train/MODEL_CARD.md](../train/MODEL_CARD.md)).
   Choose epochs, thresholds and calibration on the validation splits only.
   `eval/` is never used for tuning.
2. **Calibrate**: `go run -tags onnx ./cmd/calibrate fit -write` writes
   `calibration.json` next to the model; add the values to
   `BuiltinCalibrations` in `internal/inference/ml/calibration.go` as well.
3. **Evaluate once** on `eval/` with the final model and record the numbers
   in the model card. Do not go back to step 1 because of them; a model
   that fails the eval set is not released (as with v3).
4. **Hash** the files: `shasum -a 256 model_int8.onnx tokenizer.json config.json thresholds.json calibration.json`
   and note the sizes.
5. **Upload** the same files to Hugging Face (the repo in the manifest) and
   note the commit sha; then attach them as assets of a GitHub Release
   tagged `model-guardspec-classifier-v4` (a model release, not a `v*`
   software release).
6. **Bump the manifest**: add an entry with `version: v4`, the Hugging Face
   `revision`, the mirror
   `https://github.com/guard-spec/guard-spec/releases/download/model-guardspec-classifier-v4/{file}`
   and every file's `size` and `sha256`. Move `recommended: true` from the
   old entry to the new one, and keep the old entry so that rollback works.
7. **Check**: `go test ./internal/onnx ./internal/inference/ml`, then pull
   into an empty directory (`go run ./cmd/models pull -dir /tmp/m guardspec-classifier@v4`)
   to prove both sources serve the pinned files.
8. **CHANGELOG**: add a "Model" section under Unreleased with the version,
   what changed in the data, and the eval numbers against the previous
   version.

The next software release then ships the manifest that recommends v4.
