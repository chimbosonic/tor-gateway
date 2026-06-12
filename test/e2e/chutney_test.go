//go:build e2e
// +build e2e

/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/chimbosonic/tor-gateway/test/utils"
)

// Resource names + namespace are intentionally fixed constants — there's
// one chutney instance per kind cluster, owned by BeforeSuite.
// These must match hack/chutney/chutney.yaml.
const (
	chutneyNamespace      = "tor-gateway-chutney"
	chutneyPodName        = "chutney"
	chutneyImage          = "ghcr.io/chimbosonic/tor-gateway-chutney:dev"
	chutneyConfigMapName  = "tor-gateway-testing-network"
	chutneyConfigMapKey   = "fragment"
	chutneyMountPath      = "/etc/tor-gateway/testing-network/fragment"
	chutneyOperatorNS     = "tor-gateway-system"
	chutneyOperatorDeploy = "tor-gateway-controller-manager"
	chutneyRolloutTimeout = 2 * time.Minute
)

const (
	chutneyFreshBudget = 7 * time.Minute
	// Polling window for waitChutneyReady only; total warm-start wall clock
	// also includes injectChutneySeed (pod Running wait + kubectl cp).
	chutneyWarmReadyBudget = 5 * time.Minute
	chutneyMaxAttempts     = 3
)

// DeployChutneyAndExtractFragment is the BeforeSuite-side dispatcher: load
// (or build) the chutney image, then bootstrap the network with bounded
// retries — warm-starting from a pregen artifact when CHUTNEY_SEED_TAR is
// set, falling back to fresh bootstraps with pod recreation between
// attempts. ginkgo flake-attempts cannot retry BeforeSuite, so this loop is
// the retry layer matched to bootstrap failures. Returns the DirAuthority
// fragment for callers that want to inspect it.
func DeployChutneyAndExtractFragment() string {
	loadChutneyImage()

	seedTar := os.Getenv("CHUTNEY_SEED_TAR")
	for attempt := 1; attempt <= chutneyMaxAttempts; attempt++ {
		// Warm-start only on the first attempt: if seeded state failed
		// once, assume the artifact is the problem and bootstrap fresh.
		useSeed := seedTar != "" && attempt == 1
		budget := chutneyFreshBudget
		mode := "fresh bootstrap"
		if useSeed {
			budget = chutneyWarmReadyBudget
			mode = "warm-start (artifact)"
		}

		By(fmt.Sprintf("deploying chutney: %s, attempt %d/%d", mode, attempt, chutneyMaxAttempts))
		applyYAML(chutneyManifest(useSeed))
		if useSeed {
			injectChutneySeed(seedTar)
		}
		if waitChutneyReady(budget) {
			utils.StepSummary("chutney ready: %s, attempt %d/%d", mode, attempt, chutneyMaxAttempts)
			return finishChutneySetup()
		}
		utils.CIWarning("chutney %s attempt %d/%d not Ready within %s; recreating pod",
			mode, attempt, chutneyMaxAttempts, budget)
		utils.StepSummary("chutney bootstrap retry: %s attempt %d/%d timed out", mode, attempt, chutneyMaxAttempts)
		if attempt < chutneyMaxAttempts {
			// Recreate only when another attempt follows — the final
			// failure leaves the pod for CI's diagnostics collection.
			_, _ = utils.Run(exec.Command("kubectl", "-n", chutneyNamespace, "delete", "pod",
				chutneyPodName, "--force", "--grace-period=0", "--ignore-not-found"))
			// Pod specs are immutable (env differs between warm and fresh), so
			// the next apply must not race a still-terminating pod.
			if _, err := utils.Run(exec.Command("kubectl", "-n", chutneyNamespace, "wait",
				"--for=delete", "pod/"+chutneyPodName, "--timeout=120s")); err != nil {
				utils.CIWarning("chutney pod did not finish terminating before next attempt: %v", err)
			}
		}
	}
	Fail(fmt.Sprintf("chutney never became Ready after %d attempts", chutneyMaxAttempts))
	return "" // unreachable
}

// waitChutneyReady polls the Ready condition for up to budget. Returns false
// on timeout instead of failing, so the caller can retry.
func waitChutneyReady(budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		out, _ := utils.Run(exec.Command("kubectl", "-n", chutneyNamespace,
			"get", "pod", chutneyPodName,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}"))
		if strings.TrimSpace(out) == "True" {
			return true
		}
		time.Sleep(5 * time.Second)
	}
	return false
}

// loadChutneyImage prefers a pre-built image artifact (byte-identical to the
// one the pregen state was generated with); otherwise builds locally.
func loadChutneyImage() {
	if imgTar := os.Getenv("CHUTNEY_IMAGE_TAR"); imgTar != "" {
		By("loading the pre-built chutney image from artifact")
		_, err := utils.Run(exec.Command("docker", "load", "-i", imgTar))
		Expect(err).NotTo(HaveOccurred(), "docker load chutney image artifact")
		Expect(utils.LoadImageToKindClusterWithName(chutneyImage)).To(Succeed(),
			"kind-load chutney image from artifact")
		return
	}
	By("building and kind-loading the chutney image")
	buildAndLoadImage("image-chutney", chutneyImage)
}

// injectChutneySeed copies the pregen state tarball into the running pod and
// touches the marker the entrypoint waits for.
func injectChutneySeed(seedTar string) {
	By("injecting pre-generated chutney network state")
	Eventually(func() string {
		out, _ := utils.Run(exec.Command("kubectl", "-n", chutneyNamespace,
			"get", "pod", chutneyPodName, "-o", "jsonpath={.status.phase}"))
		return strings.TrimSpace(out)
	}, "2m", "2s").Should(Equal("Running"), "chutney pod must be Running to receive the seed")
	_, err := utils.Run(exec.Command("kubectl", "-n", chutneyNamespace,
		"exec", chutneyPodName, "--", "mkdir", "-p", "/data/seed"))
	Expect(err).NotTo(HaveOccurred(), "mkdir /data/seed")
	_, err = utils.Run(exec.Command("kubectl", "-n", chutneyNamespace,
		"cp", seedTar, chutneyPodName+":/data/seed/nodes.tar.gz"))
	Expect(err).NotTo(HaveOccurred(), "kubectl cp seed tarball")
	_, err = utils.Run(exec.Command("kubectl", "-n", chutneyNamespace,
		"exec", chutneyPodName, "--", "touch", "/data/seed/ready"))
	Expect(err).NotTo(HaveOccurred(), "touch seed-ready marker")
}

// finishChutneySetup is the post-Ready tail: extract the DirAuthority
// fragment, create the ConfigMap, patch + roll the operator.
func finishChutneySetup() string {
	By("extracting the DirAuthority block from the chutney pod")
	fragment := mustExtractChutneyFragment()

	By("creating the testing-network ConfigMap in the operator namespace")
	applyYAML(testingNetworkConfigMap(chutneyOperatorNS, fragment))

	By("patching the operator Deployment to mount + reference the fragment")
	patchOperatorForChutney()

	By("waiting for the operator rollout after the chutney patch")
	_, err := utils.Run(exec.Command("kubectl", "-n", chutneyOperatorNS,
		"rollout", "status", "deployment/"+chutneyOperatorDeploy,
		"--timeout="+chutneyRolloutTimeout.String()))
	Expect(err).NotTo(HaveOccurred(), "operator never rolled out with --testing-tor-network-file")

	return fragment
}

// TeardownChutney is the AfterSuite-side cleanup. Best-effort.
func TeardownChutney() {
	By("removing chutney from the operator Deployment")
	// Simplest reliable cleanup: undeploy the operator. AfterSuite
	// undeploys CRDs next anyway.
	_, _ = utils.Run(exec.Command("make", "undeploy", "ignore-not-found=true"))

	By("deleting the chutney namespace")
	_, _ = utils.Run(exec.Command("kubectl", "delete", "namespace", chutneyNamespace,
		"--ignore-not-found", "--wait=false"))
}

func mustExtractChutneyFragment() string {
	GinkgoHelper()
	out, err := utils.Run(exec.Command("kubectl", "-n", chutneyNamespace,
		"exec", chutneyPodName, "--",
		"sh", "-c",
		"printf 'TestingTorNetwork 1\\nClientUseIPv6 0\\n'; "+
			"grep '^DirAuthority ' /data/nodes/000a/torrc",
	))
	Expect(err).NotTo(HaveOccurred(), "kubectl exec failed extracting chutney fragment")
	fragment := strings.TrimSpace(out)
	// Defence-in-depth: refuse to proceed if the fragment is missing the
	// DirAuthority lines — otherwise we'd silently mount an empty file and
	// Tor would refuse to start with TestingTorNetwork 1.
	Expect(strings.Contains(fragment, "DirAuthority ")).To(BeTrue(),
		"chutney fragment missing DirAuthority lines:\n%s", fragment)
	Expect(strings.Count(fragment, "DirAuthority ")).To(BeNumerically(">=", 3),
		"chutney fragment has fewer than 3 DirAuthority lines:\n%s", fragment)
	return fragment + "\n"
}

func patchOperatorForChutney() {
	GinkgoHelper()
	// Two-step patch: JSON-patch appends to args (the array always exists in
	// the live object); strategic-merge handles volumes + volumeMounts (those
	// arrays are absent/null after kustomize serialisation, so JSON-patch
	// "add" with "/-" fails on them — strategic-merge creates them on the fly).
	argsPatch := fmt.Sprintf(`[
		{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--testing-tor-network-file=%s"},
		{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--testing-tor-network-namespace=%s"}
	]`, chutneyMountPath, chutneyNamespace)
	_, err := utils.Run(exec.Command("kubectl", "-n", chutneyOperatorNS,
		"patch", "deployment", chutneyOperatorDeploy,
		"--type=json", "-p", argsPatch))
	Expect(err).NotTo(HaveOccurred(), "operator args patch failed")

	volPatch := fmt.Sprintf(`{
		"spec":{
			"template":{
				"spec":{
					"containers":[{
						"name":"manager",
						"volumeMounts":[{
							"name":"testing-network",
							"mountPath":"%[2]s",
							"subPath":"%[3]s",
							"readOnly":true
						}]
					}],
					"volumes":[{
						"name":"testing-network",
						"configMap":{"name":%[1]q}
					}]
				}
			}
		}
	}`,
		chutneyConfigMapName,
		chutneyMountPath,
		chutneyConfigMapKey,
	)
	_, err = utils.Run(exec.Command("kubectl", "-n", chutneyOperatorNS,
		"patch", "deployment", chutneyOperatorDeploy,
		"--type=strategic", "-p", volPatch))
	Expect(err).NotTo(HaveOccurred(), "operator volume patch failed")
}

// chutneyManifest loads hack/chutney/chutney.yaml (shared with
// hack/chutney/pregen.sh) and substitutes the seed-mode token.
func chutneyManifest(waitSeed bool) string {
	projectDir, err := utils.GetProjectDir()
	Expect(err).NotTo(HaveOccurred(), "resolve project dir")
	raw, err := os.ReadFile(filepath.Join(projectDir, "hack", "chutney", "chutney.yaml"))
	Expect(err).NotTo(HaveOccurred(), "read hack/chutney/chutney.yaml")
	Expect(string(raw)).To(ContainSubstring("__CHUTNEY_WAIT_SEED__"),
		"hack/chutney/chutney.yaml lost the __CHUTNEY_WAIT_SEED__ token")
	v := "0"
	if waitSeed {
		v = "1"
	}
	return strings.ReplaceAll(string(raw), "__CHUTNEY_WAIT_SEED__", v)
}

func testingNetworkConfigMap(ns, fragment string) string {
	// Indent the fragment to satisfy YAML block scalar (|-) format.
	var indented strings.Builder
	for _, line := range strings.Split(fragment, "\n") {
		indented.WriteString("    ")
		indented.WriteString(line)
		indented.WriteByte('\n')
	}
	return fmt.Sprintf(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: %[1]s
  namespace: %[2]s
data:
  %[3]s: |-
%[4]s
`, chutneyConfigMapName, ns, chutneyConfigMapKey, indented.String())
}
