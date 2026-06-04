//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
)

// torClientPodYAML returns a Pod manifest for an in-cluster Tor SOCKS
// client. The Tor process %include's the chutney fragment when useChutney
// is true; otherwise it uses the public Tor network's default authorities.
// The curl sidecar is included so tests can issue fetches via the SOCKS
// proxy without needing to install curl on a separate machine.
func torClientPodYAML(ns, name string, useChutney bool) string {
	include := ""
	volMounts := `
    volumeMounts:
    - { name: tordata, mountPath: /var/lib/tor }`
	volumes := `
  - { name: tordata, emptyDir: {} }`

	if useChutney {
		include = "%include " + chutneyMountPath + "\n"
		volMounts = `
    volumeMounts:
    - { name: tordata, mountPath: /var/lib/tor }
    - { name: torrc,   mountPath: /etc/tor, readOnly: true }
    - { name: chutney, mountPath: ` + chutneyMountPath + `, subPath: ` + chutneyConfigMapKey + `, readOnly: true }`
		volumes = `
  - { name: tordata, emptyDir: {} }
  - name: torrc
    configMap:
      name: ` + name + `-torrc
  - name: chutney
    configMap:
      name: ` + chutneyConfigMapName
	}

	torrcCM := ""
	if useChutney {
		torrcCM = fmt.Sprintf(`
apiVersion: v1
kind: ConfigMap
metadata: { name: %s-torrc, namespace: %s }
data:
  torrc: |-
    SocksPort 0.0.0.0:9050
    DataDirectory /var/lib/tor/data
    %s
---
`, name, ns, include)
	}

	args := `["--SocksPort","0.0.0.0:9050","--DataDirectory","/var/lib/tor/data"]`
	if useChutney {
		// With the chutney torrc mounted, point tor at it explicitly so the
		// %include directive is honoured. images/tor has "tor" as the
		// ENTRYPOINT, so the first arg is "-f".
		args = `["-f","/etc/tor/torrc"]`
	}

	return torrcCM + fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata: { name: %[1]s, namespace: %[2]s }
spec:
  securityContext: { fsGroup: 65532 }
  containers:
  - name: tor
    image: ghcr.io/chimbosonic/tor:0.4.9
    args: %[3]s
    securityContext:
      runAsNonRoot: true
      runAsUser: 65532
      runAsGroup: 65532
      allowPrivilegeEscalation: false
      capabilities: { drop: ["ALL"] }
      readOnlyRootFilesystem: true%[4]s
  - name: curl
    image: curlimages/curl:8.11.1
    command: ["sleep","infinity"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 65532
      runAsGroup: 65532
      allowPrivilegeEscalation: false
      capabilities: { drop: ["ALL"] }
      readOnlyRootFilesystem: true
  volumes:%[5]s
`, name, ns, args, volMounts, volumes)
}

// chutneyTorClientPodYAML is the default for tests (chutney mode).
func chutneyTorClientPodYAML(ns, name string) string {
	return torClientPodYAML(ns, name, true)
}

// realtorTorClientPodYAML is for the `realtor-smoke` labelled test only.
func realtorTorClientPodYAML(ns, name string) string {
	return torClientPodYAML(ns, name, false)
}
