//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"os/exec"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/chimbosonic/tor-gateway/test/utils"
)

// copyChutneyFragmentTo copies the chutney testing-network ConfigMap from
// the operator namespace into ns. ConfigMaps cannot be mounted
// cross-namespace, so per-test namespaces need a local copy if their pods
// will mount the chutney fragment.
//
// Skipped silently when TOR_GATEWAY_E2E_MODE=realtor — the realtor smoke
// path does not use the chutney fragment.
func copyChutneyFragmentTo(ns string) {
	GinkgoHelper()
	cmd := fmt.Sprintf(
		"kubectl get configmap -n %s %s -o yaml "+
			"| sed -e 's/namespace: .*/namespace: %s/' -e '/resourceVersion:/d' -e '/uid:/d' -e '/creationTimestamp:/d' "+
			"| kubectl apply -f -",
		chutneyOperatorNS, chutneyConfigMapName, ns,
	)
	_, err := utils.Run(exec.Command("sh", "-c", cmd))
	Expect(err).NotTo(HaveOccurred(), "copy chutney ConfigMap into %s", ns)
}
