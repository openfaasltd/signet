# Signet

A lightweight OpenID Connect provider for agents and automation.

Signet is a tiny, self-contained OpenID Connect provider for automated demos,
integration tests, and single-node Kubernetes environments.

The first target is running OpenFaaS IAM flows inside a Slicer-managed k3s
cluster. Signet is deliberately standalone so it can be used by other
products later.

## Run locally

Copy `signet.example.json` to `signet.json`, or create it with:

```json
{
  "issuer": "http://127.0.0.1:8080",
  "users": [
    {
      "username": "admin",
      "password": "admin",
      "subject": "admin",
      "name": "Signet Admin",
      "email": "admin@example.com",
      "groups": ["admin"]
    }
  ],
  "clients": [
    {
      "id": "openfaas",
      "secret": "openfaas-secret",
      "redirect_urls": ["http://127.0.0.1:3000/callback"]
    }
  ]
}
```

Run the daemon with an OpenFaaS Pro, Slicer, or Inlets Pro licence:

```sh
signet up --license-file ./license.txt --config signet.json \
  --issuer http://127.0.0.1:8080 --state-dir ./signet-state
```

The ES256 signing key and provisioned users and clients are kept in the state
directory. Mount it on persistent storage in Kubernetes. A ready-to-edit
single-replica deployment is provided in `k8s/signet.yaml`; it uses the
`openfaas-license` secret and the `signet-state` PVC.

Published images are versioned at `alexellis2/signet` (starting with
`v0.0.1`); deployments must use an explicit version tag, never `latest`.

The deployment defines two Services: `signet` is the internal ClusterIP
service, and `signet-external` is the NodePort-facing service. The browser
must reach the issuer, so configure Signet, the dashboard, and the OpenFaaS
OIDC Issuer configuration with the same external issuer URL, for example
`http://192.168.1.20:30080`. The internal Service is not the issuer URL in
this topology.

Discovery is available at:

```text
http://127.0.0.1:8080/.well-known/openid-configuration
```

This is a development/demo identity provider. Do not expose it to an
untrusted network or use it for production credentials.
