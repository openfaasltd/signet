# signet Helm chart

Deploys Signet on Kubernetes. Secrets are created by the chart as Secrets and
mounted as files — never env vars.

```sh
helm install signet ./chart/signet -n openfaas --create-namespace \
  --set-json 'config=$(cat ./signet.json | jq -c)' \
  --set license.license="$(cat ./license.txt)" \
  --set github.clientId=Ov23li... \
  --set 'github.allowedLogins[0]=alexellis'
```

## State & credentials

| Item | Kind | Notes |
|------|------|-------|
| state | PVC | sealed `signet.key`, `config.json`, `admin-token` |
| `<r>-master` | Secret | key that seals the PVC; `resource-policy: keep` |
| `<r>-admin-token` | Secret | management token; `resource-policy: keep` |

The **master key and PVC are a pair** — deleting one without the other makes
signet fail closed (CrashLoopBackOff) rather than boot on plaintext. Upgrades/
uninstalls keep both Secrets, so they're safe by default.

## Retrieve

```sh
kubectl get secret signet-admin-token -n openfaas -o jsonpath='{.data.admin-token}' | base64 -d
```

## Rotate

- **Admin token** — patch the Secret + `rollout restart`. No data impact.
- **Master key / signing key** — delete the PVC **and** master Secret together,
  reinstall fresh; re-provide identities via `--set-json 'config=...'`.

## Reset (nuke)

```sh
helm uninstall signet -n openfaas
kubectl -n openfaas delete secret signet-master signet-admin-token --ignore-not-found
kubectl -n openfaas delete pvc signet-state --ignore-not-found
```

## Federation (GitHub device flow)

`github.clientId` + `allowedLogins`/`allowedOrgs` (default deny — both empty ⇒
nobody). Device entry: `https://github.com/login/device`. Requires pod egress
HTTPS to `github.com`; image ships root CAs.

## Troubleshooting

- **CrashLoop:** master key ↔ PVC mismatch → re-seal or nuke.
- **`502` / `x509: unknown authority`:** image predates the CA fix.
