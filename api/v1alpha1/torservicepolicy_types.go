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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// TorLogLevel is the verbosity level passed to the Tor daemon.
// +kubebuilder:validation:Enum=debug;info;notice;warn;err
type TorLogLevel string

// TorServicePolicySpec is the configuration for a Tor hidden service attached
// to a Gateway. This is a Direct Policy (GEP-2648): it applies only to the
// Gateway(s) referenced in TargetRefs and is not inherited by HTTPRoutes.
// +kubebuilder:validation:XValidation:rule="!has(self.vanityPrefix) || size(self.vanityPrefix) <= 6 || (has(self.vanityAcknowledgeLongRunning) && self.vanityAcknowledgeLongRunning)",message="vanityPrefix longer than 6 characters requires vanityAcknowledgeLongRunning=true"
type TorServicePolicySpec struct {
	// TargetRefs is the list of Gateways this policy configures. Each
	// reference must point at a `gateway.networking.k8s.io/v1` Gateway in
	// the same namespace as the policy. At most one TorServicePolicy may
	// be attached to a given Gateway.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(r, r.group == 'gateway.networking.k8s.io' && r.kind == 'Gateway')",message="targetRefs must reference gateway.networking.k8s.io/Gateway"
	// +required
	TargetRefs []gwv1.LocalPolicyTargetReference `json:"targetRefs"`

	// VanityPrefix requests a hidden-service ed25519 keypair whose .onion
	// address starts with this base32-encoded prefix. Generation cost grows
	// exponentially with the prefix length; the operator caps practical
	// attempts via VanityAcknowledgeLongRunning for prefixes over 6 chars.
	//
	// +kubebuilder:validation:Pattern=`^[a-z2-7]*$`
	// +kubebuilder:validation:MaxLength=8
	// +optional
	VanityPrefix string `json:"vanityPrefix,omitempty"`

	// VanityAcknowledgeLongRunning must be set to true when VanityPrefix is
	// longer than 6 characters. This is a guard against accidentally
	// running mkp224o for days or weeks.
	//
	// +optional
	VanityAcknowledgeLongRunning bool `json:"vanityAcknowledgeLongRunning,omitempty"`

	// LogLevel sets the Tor daemon's log verbosity. Defaults to "notice".
	//
	// +kubebuilder:default=notice
	// +optional
	LogLevel TorLogLevel `json:"logLevel,omitempty"`

	// PoWDefensesEnabled enables Tor's HiddenServicePoWDefensesEnabled and
	// HiddenServiceEnableIntroDoSDefense. Defaults to true; only set to
	// false if you have alternative DoS mitigation in place.
	//
	// +kubebuilder:default=true
	// +optional
	PoWDefensesEnabled *bool `json:"poWDefensesEnabled,omitempty"`

	// Resources is the resource request/limit applied to the Tor daemon
	// container in the per-Gateway pod.
	//
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`
}

// TorServicePolicyStatus reflects the operator's view of policy acceptance,
// one entry per ancestor (targeted Gateway).
type TorServicePolicyStatus struct {
	// Ancestors lists per-target acceptance status. The operator MUST set
	// at least one entry whose ControllerName matches its own
	// GatewayClass.controllerName.
	//
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Ancestors []gwv1.PolicyAncestorStatus `json:"ancestors,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:categories={gateway-api,tor-gateway},shortName=tsp
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Targets",type=string,JSONPath=`.spec.targetRefs[*].name`
// +kubebuilder:printcolumn:name="Vanity",type=string,JSONPath=`.spec.vanityPrefix`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TorServicePolicy configures the Tor daemon for one or more Gateways of
// class tor-gateway. See SECURITY.md for security-relevant defaults.
type TorServicePolicy struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec TorServicePolicySpec `json:"spec"`

	// +optional
	Status TorServicePolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// TorServicePolicyList contains a list of TorServicePolicy.
type TorServicePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []TorServicePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TorServicePolicy{}, &TorServicePolicyList{})
}
