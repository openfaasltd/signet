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

Run it with:

```sh
go run . --config signet.json --issuer http://127.0.0.1:8080
```

The ES256 signing key is created at `signet.key` on first start and reused on
subsequent starts. Mount that path on a volume when running in Kubernetes.
Refresh tokens and an admin API are intentionally not included in v0. A
ready-to-edit single-replica deployment is provided in `k8s/signet.yaml`;
replace the example credentials before applying it.

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
