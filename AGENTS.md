# AGENTS.md

Workflows and conventions for working on this repo. Read this before making
changes. It captures the local dev, browser-QA, build, and chart/release flows.

## Project

Signet is a lightweight OIDC provider (issues its own codes/tokens) that trusts
GitHub as an identity source of truth via OAuth Device Flow. Authorization is a
pure allowlist (default deny). Data is encrypted at rest.

Go binary + embedded web UI (`//go:embed web/*`) + Helm chart in `chart/signet`.

## Build & test gate

Always run the full gate on a clean tree before committing:

```sh
make gofmt        # gofmt -l -s on all .go, must be empty
go build ./...
go vet ./...
go test ./... -count=1
```

`make test` also exists but the gate above (`gofmt/build/vet/test`) is the
required pre-commit check. Node/JS is plain browser JS — there is no JS linter.

## Local dev server (for UI/JS work)

Cross-compiling is not needed locally; build a native binary and run it with an
isolated state dir so you never touch the k3s PVC.

```sh
PUBLIC_KEY=$(cat ./key.pub | base64 --wrap 2048)
go build -ldflags "-X main.PublicKey=$PUBLIC_KEY -X main.Version=dev" -o /tmp/opencode/signet .
rm -rf /tmp/opencode/srun
tmux new-session -d -s signet \
  "/tmp/opencode/signet up --listen 127.0.0.1:18082 \
   --issuer http://127.0.0.1:18082 \
   --config /tmp/opencode/scfg.json \
   --state-dir /tmp/opencode/srun \
   --license-file /tmp/opencode/license.txt"
```

- Use port `18082` locally (the cluster uses `8080:30080` NodePort).
- Kill/rebuild/restart: `tmux kill-session -t signet` then the above.
- A minimal seed config for local dev (first-run only; persisted store wins):

```json
{
  "issuer": "http://127.0.0.1:18082",
  "users": [{"username":"admin","password":"secret","subject":"admin","name":"Admin","email":"admin@example.com","groups":["admin"]}],
  "clients": [{"id":"openfaas","secret":"openfaas-secret","redirect_urls":["http://127.0.0.1:3000/callback"]}]
}
```

`PUBLIC_KEY` in `make` commands comes from `./hack/get-public-key.sh`.

## Browser QA flow (headless Firefox + gecko + vzzn)

Required because user-facing changes are embedded static assets. Verify DOM
behaviour with Selenium, then visually confirm with vzzn.

Tooling (already installed):
- Firefox binary: `/tmp/opencode/ffx/firefox/firefox`
- `geckodriver` on PATH, `xvfb-run`, `python3` with `selenium`
- `vzzn` (vision QA): `/usr/local/bin/vzzn`

Selenium driver recipe (headless):

```python
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
URL="http://127.0.0.1:18082/authorize?response_type=code&client_id=openfaas&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback"
o=Options(); o.binary_location="/tmp/opencode/ffx/firefox/firefox"; o.add_argument("--headless")
o.add_argument("--window-size=940,1150")
d=webdriver.Firefox(options=o); d.set_page_load_timeout(20)
d.get(URL)
d.save_screenshot("/tmp/opencode/out.png")
# elements: ghStart, ghCancel, ghCopy, ghCode, ghHint, ghDevice, ghFail, loginForm
d.quit()
```

Run with: `xvfb-run -a python3 script.py`. Screenshots go to `/tmp/opencode/`.

Element ids on the login page (device flow dialog):
`ghStart` (Sign in with GitHub), `ghDevice` (panel), `ghCode` (user code),
`ghHint` (expiry, e.g. `Device code expires in 09:56`), `ghCopy`, `ghCancel`,
`ghFail` (error panel), `loginForm`.

Visual confirmation with vzzn:

```bash
vzzn /tmp/opencode/out.png --prompt "Describe/verify: <what to check>. Report any defect."
```

Always cross-check rendered behaviour/variations (cancel, expired, denied) both
in DOM and by eye.

## Chart conventions (match openfaas/faas-netes)

- `image` is a **single full image string** in `values.yaml`
  (`ghcr.io/openfaasltd/signet:latest`) — not a repo/tag split.
  `registryPrefix` rewrites registries via the `signet.image` helper.
- `imagePullPolicy` defaults to **`Always`** (mutable `:latest`).
- Bump the chart version with a **patch-only** bump via arkade:
  `make bump-chart` == `arkade chart bump --file ./chart/signet/Chart.yaml -w`.
  Never bump minor/major.
- `make verify-chart` / `make upgrade-chart` use arkade against
  `./chart/signet/values.yaml` (top-level `image:` is required for arkade to
  pick it up).
- `make charts` = `verify-chart` + `charts-only` (helm package + repo index).

## Sandbox e2e deploy (this VM)

Cluster k3s on `172.16.0.2`. Chart release `signet` in namespace `openfaas`,
NodePort `8080:30080`. Overrides live in `docs/values-e2e.yaml` (e2e image
`ttl.sh/signet-e2e:<tag>`, not `ghcr`).

```sh
LIC=$(cat /tmp/opencode/license.txt | tr -d '\n')
helm upgrade signet chart/signet -f docs/values-e2e.yaml --namespace openfaas \
  --set license.enabled=true \
  --set license.secretName=signet-license \
  --set license.license="$LIC" \
  --set github.clientId=Ov23lijaZHFp8E932h19 \
  --set 'github.allowedLogins[0]=alexellis'
```

Build + push an e2e image and bump the tag in `docs/values-e2e.yaml`:

```sh
PUBLIC_KEY=$(cat ./key.pub | base64 --wrap 2048)
GIT_COMMIT=$(git rev-parse --short HEAD)
docker build \
  --build-arg PUBLIC_KEY="$PUBLIC_KEY" --build-arg VERSION=dev --build-arg GIT_COMMIT="$GIT_COMMIT" \
  -t ttl.sh/signet-e2e:<next> .
docker push ttl.sh/signet-e2e:<next>
```

The e2e image is `ttl.sh/signet-e2e:<hh>` (hour-incrementing tag).
After deploy, restart the pod to force re-pull (`imagePullPolicy: Always`):

```sh
kubectl -n openfaas rollout restart deployment/signet
kubectl -n openfaas rollout status deployment/signet --timeout=60s
```

Verify health/UI at `http://172.16.0.2:30080/healthz` (expect 200). For
authorize flows from this VM use the `openfaas` client whose only registered
redirect is `http://127.0.0.1:3000/callback` — port 3000 must be listening or
the redirect fails.

## Commit etiquette

- Inspect `git status`, `git diff`, `git log --oneline -5` before committing.
- Stage only intended files; never stage secrets or `geckodriver.log`
  (not gitignored) unless intended.
- Keep commit messages concise, matching repo style (imperative, lowercase,
  e.g. `Fix cancel showing fail page`).
- Bump chart patch version before shipping chart changes (`make bump-chart`).
