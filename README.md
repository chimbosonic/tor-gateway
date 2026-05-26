# tor-gateway

A Kubernetes [Gateway API](https://gateway-api.sigs.k8s.io/) conformant operator that exposes in-cluster `Service`s as Tor v3 hidden services (`.onion` URLs).

Drop in a `Gateway` of class `tor-gateway` and one or more `HTTPRoute`s, and the operator provisions a Tor daemon, manages its ed25519 keys, and publishes the resulting `.onion` address in `Gateway.status.addresses`.

## Status

Pre-alpha. See [the design plan](https://github.com/chimbosonic/tor-gateway/blob/main/docs/PLAN.md) and [`SECURITY.md`](./SECURITY.md).

## Quickstart

```sh
make kind-up
helm install tor-gateway ./charts/tor-gateway
kubectl apply -f config/samples/blog-gateway.yaml
kubectl get gateway blog -o jsonpath='{.status.addresses[0].value}'
```

## Features (v1 target)

- Gateway API v1.5 conformance (Gateway + HTTPRoute + ReferenceGrant).
- Persistent v3 keys via Secrets.
- v3 client authorization via `TorClientAuthPolicy`.
- HA via onionbalance via `OnionBalancePolicy`.
- Vanity address prefixes via `TorServicePolicy.vanityPrefix` (on-demand `mkp224o` Job).
- Prometheus metrics, cosign-signed images, SBOM.

## License

Apache 2.0.
