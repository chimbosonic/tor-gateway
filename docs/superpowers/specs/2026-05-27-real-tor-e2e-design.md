# Real-Tor data-plane e2e — design

- **Date:** 2026-05-27
- **Status:** Implemented (`images/tor` daemon image, `test/e2e/dataplane_test.go`, subdir HS paths in `names.go`). As-built: the Tor image ref is `tor:0.4.9`, superseding the `0.4.8-latest` placeholder used throughout this doc.
- **Owner:** Alexis Lowe

## Context

The operator provisions a Tor v3 hidden service per `Gateway` and an in-pod
`router` sidecar that fans HTTPRoute traffic out to in-cluster Service
backends. `router.New()` is now wired (informer → route table → reverse
proxy) and covered by unit + envtest. What is *not* yet proven is the
**data path**: that a request to the published `.onion`, over a real Tor
circuit, actually reaches the right backend through the router.

The existing e2e suite (`test/e2e/`, build tag `e2e`, Ginkgo) deliberately
uses placeholder images and asserts only the control plane (reconciler
resource generation, status, OwnerReference cascade) — see the comment in
`test/e2e/gateway_test.go`. This work adds the deferred data-plane suite it
references.

Two things block that test today:
1. There is **no usable Tor daemon image**. The operator defaults to
   `ghcr.io/chimbosonic/tor:0.4.8-latest`, which does not exist/resolve, and
   the repo contains no Tor image definition.
2. There is **no client capable of reaching a `.onion`** in the harness.

## Goals

- A hardened Tor daemon image built in this repo, compatible with the
  operator's container contract.
- A Ginkgo e2e spec that deploys a Gateway + HTTPRoute with two backends and
  asserts, over a real `.onion` fetched through Tor, that path-based routing
  works (`/` → backend-A, `/api` → backend-B).
- The spec runs in the standard `make test-e2e` flow and **blocks the PR
  gate** like the rest of the suite.

## Non-goals (YAGNI)

- Private Tor network / chutney. We use the **public Tor network**.
- onionbalance / HA data path, client-auth over Tor, vanity addresses.
- Automatic in-test retry. Tor instability is acceptable; engineers re-run.

## Decisions (settled during brainstorming)

| Question | Decision |
|---|---|
| Tor network | Public Tor network. |
| Tor image | Build a hardened image in this repo. |
| How the test reaches the `.onion` | In-cluster `tor-client` pod (Tor SOCKS sidecar + curl sidecar), driven via `kubectl exec`. |
| Assertion scope | Prove routing: two paths → two distinct backends. |
| Gating | None. Normal spec under `make test-e2e`; blocks the PR gate. |

## Deliverable A — hardened Tor daemon image

**File:** `images/tor/Dockerfile` (Alpine-based; pin Alpine and the `tor`
package version).

Requirements driven by the operator's container spec
(`internal/controller/gateway_resources.go`):
- `ENTRYPOINT ["tor"]` — the operator passes `Args: ["-f", "/etc/tor/torrc"]`
  and sets no `Command`.
- Runs as **nonroot UID 65532** with a **read-only root filesystem** and all
  capabilities dropped (`hardenedContainerSec()`). Tor must write only to the
  operator's mounted emptyDirs: `DataDirectory` (`data` volume) and
  `HiddenServiceDir` (`hsDir` volume, prepared by `tor-init`).

**Makefile:** add `image-tor` (mirrors `image-router`) and a `TOR_IMG`
variable; wire into the `images` aggregate and `docker-push`.

**Image reference wiring for the e2e:** the operator requests
`ghcr.io/chimbosonic/tor:0.4.8-latest` (manager flag default,
`cmd/manager/main.go`). The e2e tags/loads the locally built Tor image under
that exact ref and relies on `imagePullPolicy: PullIfNotPresent` so the pod
uses the loaded image without pulling. (Alternative considered: pass
`--tor-image` to the operator deploy; rejected as extra plumbing unless the
tag-match proves insufficient.)

## Deliverable B — data-plane e2e spec

**File:** `test/e2e/dataplane_test.go` (build tag `e2e`; a normal Ginkgo
`Describe`, no special label or skip guard).

### Image prerequisites

The shared `BeforeSuite` (`test/e2e/e2e_suite_test.go`) continues to build,
`kind load`, and deploy only the **manager**. The dataplane spec's
`BeforeAll` builds + `kind load`s the three pod images the data path needs:
- `tor-gateway-router:dev`
- `tor-gateway-tor-init:dev`
- `tor:0.4.8-latest` (the new image, tagged to the operator's expected ref)

The operator (already deployed by `BeforeSuite`) does not need these images
until the Gateway is created, so loading them in the spec's `BeforeAll` is
sufficient and keeps the operator-only specs unaffected.

### Test resources

- A `tor-gateway` GatewayClass and an isolated namespace.
- **Two backends** using `hashicorp/http-echo` (path-agnostic; returns a
  fixed body): `-text=backend-A` and `-text=backend-B`, each a Deployment +
  Service. Wait for Ready.
- A **Gateway** (listener `onion`, port 80, protocol
  `torgateway.io/HiddenService`).
- An **HTTPRoute** with two rules:
  - `PathPrefix /api` → backend-B Service
  - `PathPrefix /` → backend-A Service

  (Exact-vs-prefix precedence is unit-tested; here we rely on prefix length
  precedence — `/api` outranks `/` — to route `/api` to B and everything
  else to A.)

### Data flow

```
kubectl exec (curl sidecar)
  → curl --socks5-hostname 127.0.0.1:9050 http://<onion>/<path>
    → tor-client SOCKS (sidecar, public Tor)
      → [Tor network: HS descriptor lookup]
        → operator's Tor pod (HiddenServicePort 80 → 127.0.0.1:9080)
          → router sidecar (matches <path> against HTTPRoute rules)
            → backend-A / backend-B Service
              → http-echo response body ("backend-A" / "backend-B")
```

### Steps

1. Create namespace + GatewayClass.
2. Apply the two backend Deployments + Services; wait Ready.
3. Apply the Gateway + HTTPRoute.
4. Wait for: `Gateway.status.addresses[0].value` matches
   `^[a-z2-7]{56}\.onion$`; `Programmed=True`; the Tor Deployment Available
   (its pods now run real images).
5. Deploy a `tor-client` pod:
   - container `tor`: the new Tor image as a SOCKS proxy, invoked with
     explicit args (`tor --SocksPort 127.0.0.1:9050 --DataDirectory <dir>`,
     `<dir>` on an emptyDir) — running `tor` bare would fall back to its
     default DataDirectory, which fails under a read-only rootfs as UID
     65532. This client pod is not subject to the operator's hardening; we
     define its spec, so a relaxed securityContext (writable `<dir>`) is
     acceptable.
   - container `curl`: `curlimages/curl` with `command: ["sleep","infinity"]`,
     sharing the pod network namespace (localhost reaches the SOCKS port).
6. `Eventually` (≈5–8 min, polling ~10s): `kubectl exec tor-client -c curl --
   curl -s --socks5-hostname 127.0.0.1:9050 http://<onion>/` returns
   `backend-A`, and `…/api` returns `backend-B`. The long window covers Tor
   bootstrap on both sides plus HS descriptor publish and client lookup.

### Teardown

`AfterAll`: delete the namespace, GatewayClass, and `tor-client` pod
(best-effort; errors ignored).

## Resolved during a debugging spike (2026-05-27)

- **The per-Gateway Tor pod cannot start as configured today** — confirmed
  empirically on a kind cluster with the built Tor image (Tor 0.4.9.8). Root
  cause: the operator points `HiddenServiceDir` (`/var/lib/tor/hs`) and
  `DataDirectory` (`/var/lib/tor/data`) at the emptyDir **mount roots**. The
  pod sets `fsGroup: 65532`, which makes those `root:65532` (mode 2777) — the
  **owner stays root**. Two failures result, both because group ownership is
  not enough:
  1. `tor-init`'s `FixPermissions` does `chmod 0700` on the mount root; as
     UID 65532 (not owner) this is `EPERM` and the init container crashes.
  2. Tor refuses to start: `/var/lib/tor/hs is not owned by this user (...,
     65532) but by root (0)` → `Reading config failed`.
- **Fix (validated):** use process-created subdirectories inside the
  group-writable emptyDirs. With `HiddenServiceDir /var/lib/tor/hs/hs` and
  `DataDirectory /var/lib/tor/data/data`: `tor-init`'s existing `MkdirAll(dst)`
  creates the HS subdir owned by 65532 (parent is group-writable + setgid) so
  its `chmod` succeeds, and Tor creates the DataDirectory subdir itself
  (0700, owned 65532). A probe pod confirmed chmod EPERM on the mount root vs.
  success on a self-created subdir; a Tor pod with the subdir paths
  bootstrapped to 95% against the public Tor network and generated a working
  `.onion`. **Operator change:** the two dir values in `gateway_resources.go`
  (which feed both the rendered torrc and the `tor-init --dst` arg), plus the
  golden torrc fixtures and `gateway_resources_test`. `tor-init`'s Go code is
  unchanged.

## Remaining risks
- **Public Tor egress.** If the test environment blocks outbound Tor, the
  suite fails. Accepted: the test is in the gate and engineers re-run.
- **Image-reference match.** Confirm the deployed operator actually consumes
  the kind-loaded images (verify the tag-match approach; fall back to
  `--tor-image`/deploy flags if needed).
- **http-echo path behavior.** Confirm `hashicorp/http-echo` returns its
  fixed `-text` on every path (it ignores the request path), so routing —
  not the backend — decides which body comes back.

## Verification of this work

- Tor image: builds via `make image-tor`; smoke-run that `tor --version`
  works and the container starts as UID 65532 with a read-only rootfs against
  a representative torrc + emptyDir mounts.
- e2e spec: green under `make test-e2e` against a kind cluster with the four
  images loaded.
