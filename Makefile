# Image URL to use all building/pushing image targets
IMG ?= controller:latest
# YEAR defines the year value used for substituting the YEAR placeholder in the boilerplate header.
YEAR ?= $(shell date +%Y)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL is the container CLI used by all image-related targets and
# by kind's image loading. Defaults to docker (matches CI's ubuntu-latest
# runners, Rancher Desktop, Docker Desktop, and Colima). Set
# CONTAINER_TOOL=podman to use podman locally; the kind provider switch
# below routes accordingly.
CONTAINER_TOOL ?= docker
REGISTRY ?= ghcr.io/chimbosonic
IMAGE_TAG ?= dev
MANAGER_IMG ?= $(REGISTRY)/tor-gateway-manager:$(IMAGE_TAG)
ROUTER_IMG  ?= $(REGISTRY)/tor-gateway-router:$(IMAGE_TAG)
OBREFRESH_IMG ?= $(REGISTRY)/tor-gateway-obrefresh:$(IMAGE_TAG)
TORINIT_IMG ?= $(REGISTRY)/tor-gateway-tor-init:$(IMAGE_TAG)
# Tor daemon image. Tor is upstream software versioned independently of our
# component images, so it has its own tag (not IMAGE_TAG): the Tor minor that
# images/tor's Alpine base packages (bump both together). The default must
# match the operator's --tor-image default (cmd/manager/main.go) so a
# kind-loaded image is used via PullIfNotPresent; override with TOR_IMAGE_TAG.
TOR_IMAGE_TAG ?= 0.4.9
TOR_IMG ?= $(REGISTRY)/tor:$(TOR_IMAGE_TAG)
MKP224O_IMG ?= $(REGISTRY)/mkp224o:$(IMAGE_TAG)
ONIONBALANCE_IMG ?= $(REGISTRY)/tor-gateway-onionbalance:$(IMAGE_TAG)
VANITYFINALIZE_IMG ?= $(REGISTRY)/tor-gateway-vanity-finalize:$(IMAGE_TAG)
CHUTNEY_IMG ?= $(REGISTRY)/tor-gateway-chutney:$(IMAGE_TAG)
IMG ?= $(MANAGER_IMG)

# When CONTAINER_TOOL is podman, point kind at podman too so the cluster
# itself, image builds, and `kind load docker-image` all share one
# container runtime. CI sets CONTAINER_TOOL=docker (the GitHub-hosted
# ubuntu runners ship docker), so this guard leaves the docker path
# untouched there.
ifeq ($(CONTAINER_TOOL),podman)
export KIND_EXPERIMENTAL_PROVIDER := podman
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt",year=$(YEAR) paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

# TODO(user): To use a different vendor for e2e tests, modify the setup under 'tests/e2e'.
# The default setup assumes Kind is pre-installed and builds/loads the Manager Docker image locally.
# kubectl kuberc is disabled by default for test isolation; enable with:
# - KUBECTL_KUBERC=true
# CertManager is installed by default; skip with:
# - CERT_MANAGER_INSTALL_SKIP=true
KIND_CLUSTER ?= tor-gateway-test-e2e

.PHONY: setup-test-e2e
setup-test-e2e: ## Set up a Kind cluster for e2e tests if it does not exist
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@case "$$($(KIND) get clusters)" in \
		*"$(KIND_CLUSTER)"*) \
			echo "Kind cluster '$(KIND_CLUSTER)' already exists. Skipping creation." ;; \
		*) \
			echo "Creating Kind cluster '$(KIND_CLUSTER)'..."; \
			$(KIND) create cluster --name $(KIND_CLUSTER) ;; \
	esac

.PHONY: test-e2e
test-e2e: setup-test-e2e manifests generate fmt vet ## Run the e2e tests. Expected an isolated environment using Kind.
	# CERT_MANAGER_INSTALL_SKIP: the kubebuilder e2e harness installs
	# cert-manager so its scaffolded webhook tests can run. tor-gateway
	# has no admission webhooks, so cert-manager is dead weight that
	# also adds ~1m of cluster setup and the occasional flaky install.
	# -timeout 45m: several specs wait on real Tor hidden-service descriptor
	# publish/lookup (~8m budget each), run serially; the default 10m would
	# kill the binary mid-suite.
	KIND=$(KIND) KIND_CLUSTER=$(KIND_CLUSTER) CERT_MANAGER_INSTALL_SKIP=true \
		go test -tags=e2e -timeout 45m ./test/e2e/ -v -ginkgo.v
	$(MAKE) cleanup-test-e2e

.PHONY: cleanup-test-e2e
cleanup-test-e2e: ## Tear down the Kind cluster used for e2e tests
	@$(KIND) delete cluster --name $(KIND_CLUSTER)

# Gateway API CRDs and conformance targets.
# Both pull from the gateway-api Go module cache so the version stays in
# lockstep with go.mod (no separate version-tracking surface).
GATEWAY_API_DIR ?= $(shell go list -m -f '{{.Dir}}' sigs.k8s.io/gateway-api)
GATEWAY_API_CRDS_DIR ?= $(GATEWAY_API_DIR)/config/crd/standard

.PHONY: install-gateway-api-crds
install-gateway-api-crds: ## Apply gateway-api standard-channel CRDs to the current kube context.
	$(KUBECTL) apply -f $(GATEWAY_API_CRDS_DIR)

.PHONY: test-conformance
test-conformance: setup-test-e2e manifests generate fmt vet ## Verify the deployed operator satisfies the Gateway API status contract (Kind).
	@command -v $(KIND) >/dev/null 2>&1 || { echo "kind required for conformance"; exit 1; }
	$(MAKE) docker-build IMG=$(MANAGER_IMG)
	$(KIND) load docker-image $(MANAGER_IMG) --name $(KIND_CLUSTER)
	$(MAKE) install-gateway-api-crds
	$(MAKE) install
	$(MAKE) deploy IMG=$(MANAGER_IMG)
	# `make deploy` installs the operator only; register the GatewayClass
	# our API-shape test points at.
	$(KUBECTL) apply -f config/samples/gatewayclass.yaml
	# Custom API-shape conformance (see test/conformance): a Tor hidden-
	# service gateway can't satisfy the upstream GATEWAY-HTTP traffic
	# profile (no clearnet HTTP, no IP-reachable address), so we assert the
	# subset of the Gateway API status contract we DO implement.
	go test -tags=conformance -timeout 10m ./test/conformance -v
	$(MAKE) cleanup-test-e2e

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build all binaries (manager, router, obrefresh, tor-init).
	go build -trimpath -o bin/manager ./cmd/manager
	go build -trimpath -o bin/router ./cmd/router
	go build -trimpath -o bin/obrefresh ./cmd/obrefresh
	go build -trimpath -o bin/tor-init ./cmd/tor-init

.PHONY: run
run: manifests generate fmt vet ## Run the manager from your host.
	go run ./cmd/manager

# Build all container images. Defaults to docker; override via CONTAINER_TOOL=podman.
.PHONY: images
images: image-manager image-router image-obrefresh image-tor-init image-tor image-mkp224o image-onionbalance image-vanity-finalize image-chutney ## Build all container images.

.PHONY: image-manager
image-manager:
	$(CONTAINER_TOOL) build --build-arg BINARY=manager -t $(MANAGER_IMG) .

.PHONY: image-router
image-router:
	$(CONTAINER_TOOL) build --build-arg BINARY=router -t $(ROUTER_IMG) .

.PHONY: image-obrefresh
image-obrefresh:
	$(CONTAINER_TOOL) build --build-arg BINARY=obrefresh -t $(OBREFRESH_IMG) .

.PHONY: image-tor-init
image-tor-init:
	$(CONTAINER_TOOL) build --build-arg BINARY=tor-init -t $(TORINIT_IMG) .

.PHONY: image-tor
image-tor:
	$(CONTAINER_TOOL) build -t $(TOR_IMG) images/tor

.PHONY: image-mkp224o
image-mkp224o:
	$(CONTAINER_TOOL) build -t $(MKP224O_IMG) images/mkp224o

.PHONY: image-onionbalance
image-onionbalance:
	$(CONTAINER_TOOL) build -t $(ONIONBALANCE_IMG) images/onionbalance

.PHONY: image-vanity-finalize
image-vanity-finalize:
	$(CONTAINER_TOOL) build --build-arg BINARY=vanity-finalize -t $(VANITYFINALIZE_IMG) .

.PHONY: image-chutney
image-chutney: ## Build the chutney testing-network image (e2e-only).
	$(CONTAINER_TOOL) build -t $(CHUTNEY_IMG) images/chutney

# Back-compat single-image target. Honors IMG=... so callers (notably the
# e2e suite's BeforeSuite, which invokes `make docker-build IMG=...`) tag
# the image with their chosen name rather than the project default.
.PHONY: docker-build
docker-build: ## Build the manager image with the supplied IMG (or MANAGER_IMG default).
	$(MAKE) image-manager MANAGER_IMG=$(IMG)

.PHONY: docker-push
docker-push: ## Push all images.
	$(CONTAINER_TOOL) push $(MANAGER_IMG)
	$(CONTAINER_TOOL) push $(ROUTER_IMG)
	$(CONTAINER_TOOL) push $(OBREFRESH_IMG)
	$(CONTAINER_TOOL) push $(TORINIT_IMG)
	$(CONTAINER_TOOL) push $(TOR_IMG)
	$(CONTAINER_TOOL) push $(MKP224O_IMG)
	$(CONTAINER_TOOL) push $(ONIONBALANCE_IMG)
	$(CONTAINER_TOOL) push $(VANITYFINALIZE_IMG)

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name tor-gateway-builder
	$(CONTAINER_TOOL) buildx use tor-gateway-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm tor-gateway-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default > dist/install.yaml

.PHONY: chart-smoke
chart-smoke: setup-test-e2e install-gateway-api-crds ## Install the chart in kind and verify the operator reconciles a Gateway.
	$(MAKE) docker-build IMG=$(MANAGER_IMG)
	$(KIND) load docker-image $(MANAGER_IMG) --name $(KIND_CLUSTER)
	$(HELM) upgrade --install tor-gateway charts/tor-gateway \
		--namespace tor-gateway-system --create-namespace \
		--set manager.image.repository=$(REGISTRY)/tor-gateway-manager \
		--set manager.image.tag=$(IMAGE_TAG)
	$(KUBECTL) -n tor-gateway-system wait --for=condition=Available deployment \
		-l app.kubernetes.io/name=tor-gateway --timeout=120s
	$(KUBECTL) apply -f test/chart/gateway.yaml
	# The operator can only set these conditions if its RBAC + the CRDs are present.
	$(KUBECTL) -n default wait --for=jsonpath='{.status.conditions[?(@.type=="Accepted")].status}'=True   gateway/smoke --timeout=120s
	$(KUBECTL) -n default wait --for=jsonpath='{.status.conditions[?(@.type=="Programmed")].status}'=True gateway/smoke --timeout=120s
	@appver=$$($(HELM) show chart charts/tor-gateway | $(YQ) '.appVersion'); \
		img=$$($(KUBECTL) -n default get pod -l torgateway.io/gateway=smoke \
		-o jsonpath='{.items[0].spec.containers[?(@.name=="router")].image}'); \
		echo "router image: $$img (expected …router:$$appver)"; \
		case "$$img" in *tor-gateway-router:$$appver) ;; *) echo "ERROR: router image is $$img, expected …router:$$appver"; exit 1;; esac
	@echo "chart-smoke PASS: chart-installed operator reconciled the Gateway"
	$(MAKE) cleanup-test-e2e

# chart-sync requires yq v4 (mikefarah/yq); v3's `yq r` syntax silently emits wrong output.
.PHONY: chart-sync
chart-sync: ## Sync the Helm chart's RBAC rules + CRDs from config/ (source of truth).
	@mkdir -p charts/tor-gateway/files/rbac charts/tor-gateway/files/crds
	$(YQ) '.rules' config/rbac/role.yaml                  > charts/tor-gateway/files/rbac/manager-role-rules.yaml
	$(YQ) '.rules' config/rbac/leader_election_role.yaml  > charts/tor-gateway/files/rbac/leader-election-role-rules.yaml
	$(YQ) '.rules' config/rbac/metrics_auth_role.yaml     > charts/tor-gateway/files/rbac/metrics-auth-role-rules.yaml
	$(YQ) '.rules' config/rbac/metrics_reader_role.yaml   > charts/tor-gateway/files/rbac/metrics-reader-role-rules.yaml
	@rm -f charts/tor-gateway/files/crds/*.yaml
	# CRDs carry helm.sh/resource-policy=keep so `helm uninstall` won't delete them
	# (which would cascade-delete users' policy custom resources).
	@for f in config/crd/bases/*.yaml; do \
		$(YQ) '.metadata.annotations."helm.sh/resource-policy" = "keep"' "$$f" \
			> "charts/tor-gateway/files/crds/$$(basename "$$f")"; \
	done

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" apply -f -; else echo "No CRDs to install; skipping."; fi

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -; else echo "No CRDs to delete; skipping."; fi

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
KUBECTL ?= kubectl
KIND ?= kind
HELM ?= helm
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
YQ ?= yq

## Tool Versions
KUSTOMIZE_VERSION ?= v5.8.1
CONTROLLER_TOOLS_VERSION ?= v0.20.1

#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell v='$(call gomodver,sigs.k8s.io/controller-runtime)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_VERSION manually (controller-runtime replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?([0-9]+)\.([0-9]+).*/release-\1.\2/')

#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell v='$(call gomodver,k8s.io/api)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_K8S_VERSION manually (k8s.io/api replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

GOLANGCI_LINT_VERSION ?= v2.11.4
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))
	@test -f .custom-gcl.yml && { \
		echo "Building custom golangci-lint with plugins..." && \
		$(GOLANGCI_LINT) custom --destination $(LOCALBIN) --name golangci-lint-custom && \
		mv -f $(LOCALBIN)/golangci-lint-custom $(GOLANGCI_LINT); \
	} || true

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef
