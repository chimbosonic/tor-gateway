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
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/chimbosonic/tor-gateway/test/utils"
)

// Resource names + namespace are intentionally fixed constants — there's
// one chutney instance per kind cluster, owned by BeforeSuite.
const (
	chutneyNamespace      = "tor-gateway-chutney"
	chutneyPodName        = "chutney"
	chutneyServiceName    = "chutney-network"
	chutneyImage          = "ghcr.io/chimbosonic/tor-gateway-chutney:dev"
	chutneyConfigMapName  = "tor-gateway-testing-network"
	chutneyConfigMapKey   = "fragment"
	chutneyMountPath      = "/etc/tor-gateway/testing-network/fragment"
	chutneyOperatorNS     = "tor-gateway-system"
	chutneyOperatorDeploy = "tor-gateway-controller-manager"
	chutneyReadyTimeout   = 12 * time.Minute
	chutneyRolloutTimeout = 2 * time.Minute
)

// DeployChutneyAndExtractFragment is the BeforeSuite-side dispatcher:
//  1. Build + kind-load the chutney image.
//  2. Apply the chutney namespace + Pod + Service.
//  3. Wait for the Pod's readiness probe to pass.
//  4. Extract the DirAuthority block from inside the pod.
//  5. Create the tor-gateway-testing-network ConfigMap.
//  6. Patch the operator Deployment to mount + reference it.
//
// Returns the fragment string for callers that want to inspect it.
func DeployChutneyAndExtractFragment() string {
	By("building and kind-loading the chutney image")
	buildAndLoadImage("image-chutney", chutneyImage)

	By("applying the chutney namespace + Pod + Service")
	applyYAML(chutneyManifest())

	By("waiting for the chutney pod to be Ready")
	Eventually(func() (string, error) {
		return utils.Run(exec.Command("kubectl", "-n", chutneyNamespace,
			"get", "pod", chutneyPodName,
			"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}"))
	}, chutneyReadyTimeout, "5s").Should(Equal("True"),
		"chutney pod never became Ready (./chutney verify did not return 0)")

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

func chutneyManifest() string {
	return `
apiVersion: v1
kind: Namespace
metadata:
  name: ` + chutneyNamespace + `
---
apiVersion: v1
kind: Service
metadata:
  name: ` + chutneyServiceName + `
  namespace: ` + chutneyNamespace + `
spec:
  selector: { app: chutney }
  ports:
  - { name: dir-0, port: 7000, targetPort: 7000 }
  - { name: dir-1, port: 7001, targetPort: 7001 }
  - { name: dir-2, port: 7002, targetPort: 7002 }
---
apiVersion: v1
kind: Pod
metadata:
  name: ` + chutneyPodName + `
  namespace: ` + chutneyNamespace + `
  labels: { app: chutney }
spec:
  restartPolicy: OnFailure
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
  containers:
  - name: chutney
    image: ` + chutneyImage + `
    imagePullPolicy: Never
    env:
    - name: POD_IP
      valueFrom:
        fieldRef:
          fieldPath: status.podIP
    volumeMounts:
    - { name: data, mountPath: /data }
    readinessProbe:
      exec:
        command: ["./chutney", "verify", "networks/k8s-mini"]
      initialDelaySeconds: 60
      periodSeconds: 15
      timeoutSeconds: 60  # was: 20 — too tight for cold CI; verify needs longer when network is bootstrapping
      failureThreshold: 30
    livenessProbe:
      exec:
        command: ["pgrep", "tor"]
      initialDelaySeconds: 60
      periodSeconds: 60
      failureThreshold: 5
    resources:
      requests: { cpu: "500m", memory: "1Gi" }
      limits:   { cpu: "1",    memory: "2Gi" }
  volumes:
  - { name: data, emptyDir: {} }
`
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
