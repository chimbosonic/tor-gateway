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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// ClientAuthMode controls how the Tor service treats requests from clients
// that did not present an authorized x25519 keypair.
// +kubebuilder:validation:Enum=Strict;Audit
type ClientAuthMode string

const (
	// ClientAuthModeStrict rejects unauthorized clients at the Tor descriptor
	// layer. This is the default and the secure choice.
	ClientAuthModeStrict ClientAuthMode = "Strict"

	// ClientAuthModeAudit logs that an auth policy applies but mounts no
	// authorized_clients dir; the Tor service accepts all clients as if no
	// policy were set. Use during a roll-out to preview the change before
	// flipping to Strict; not for production.
	ClientAuthModeAudit ClientAuthMode = "Audit"
)

// ClientsSecretRef references a Secret holding authorized client x25519
// public keys. Each entry in Secret.Data is interpreted as one client's
// base32-encoded x25519 public key (the part after "descriptor:x25519:" in
// the standard Tor .auth format). The map key becomes the on-disk filename
// (<key>.auth) and the client's logical label.
//
// Cross-namespace references require a ReferenceGrant in the Secret's
// namespace authorizing this policy.
type ClientsSecretRef struct {
	// Name of the Secret.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	Name string `json:"name"`

	// Namespace of the Secret. Defaults to the policy's namespace.
	//
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// TorClientAuthPolicySpec configures v3 client authorization for a Gateway.
// This is a Direct Policy (GEP-2648).
type TorClientAuthPolicySpec struct {
	// TargetRefs is the list of Gateways this policy applies to. Must
	// reference gateway.networking.k8s.io/v1 Gateways.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(r, r.group == 'gateway.networking.k8s.io' && r.kind == 'Gateway')",message="targetRefs must reference gateway.networking.k8s.io/Gateway"
	// +required
	TargetRefs []gwv1.LocalPolicyTargetReference `json:"targetRefs"`

	// ClientsSecretRef points at the Secret containing authorized client
	// x25519 public keys.
	//
	// +required
	ClientsSecretRef ClientsSecretRef `json:"clientsSecretRef"`

	// Mode controls behavior for unauthorized clients. Defaults to Strict.
	//
	// +kubebuilder:default=Strict
	// +optional
	Mode ClientAuthMode `json:"mode,omitempty"`
}

// TorClientAuthPolicyStatus reflects acceptance per ancestor Gateway.
type TorClientAuthPolicyStatus struct {
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Ancestors []gwv1.PolicyAncestorStatus `json:"ancestors,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:categories={gateway-api,tor-gateway},shortName=tcap
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Targets",type=string,JSONPath=`.spec.targetRefs[*].name`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// TorClientAuthPolicy enables Tor v3 client authorization on one or more
// Gateways. Only clients holding a matching x25519 private key can resolve
// the .onion descriptor.
type TorClientAuthPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec TorClientAuthPolicySpec `json:"spec"`

	// +optional
	Status TorClientAuthPolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// TorClientAuthPolicyList contains a list of TorClientAuthPolicy.
type TorClientAuthPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []TorClientAuthPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TorClientAuthPolicy{}, &TorClientAuthPolicyList{})
}
