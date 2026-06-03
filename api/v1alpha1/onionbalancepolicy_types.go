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

// MasterKeySecretRef references the Secret holding the onionbalance frontend
// master ed25519 key. The operator NEVER auto-generates this Secret because
// losing the master key permanently invalidates the public .onion address.
// The user is expected to bootstrap it once (via mkp224o or `tor`-genkey).
type MasterKeySecretRef struct {
	// Name of the Secret.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	Name string `json:"name"`

	// Namespace of the Secret. Defaults to the policy's namespace.
	// Cross-namespace requires a ReferenceGrant.
	//
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// OnionBalancePolicySpec configures HA via the onionbalance daemon for a
// Gateway. Direct Policy (GEP-2648): each backend instance gets its own
// ed25519 key and acts as an introduction-point provider behind the master
// .onion address.
type OnionBalancePolicySpec struct {
	// TargetRefs is the list of Gateways this policy applies to. Must
	// reference gateway.networking.k8s.io/v1 Gateways.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(r, r.group == 'gateway.networking.k8s.io' && r.kind == 'Gateway')",message="targetRefs must reference gateway.networking.k8s.io/Gateway"
	// +required
	TargetRefs []gwv1.LocalPolicyTargetReference `json:"targetRefs"`

	// Replicas is the number of backend Tor instances that publish
	// introduction points behind the master onion address. Capped at 8
	// to match the onionbalance-config generator default; the Tor spec
	// ceiling at the current N_INTROS_PER_INSTANCE=2 is 10 backends.
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=8
	// +kubebuilder:default=3
	// +required
	Replicas int32 `json:"replicas"`

	// RefreshInterval is the minimum interval between onionbalance config
	// rewrites in the frontend pod when backend instances change.
	//
	// +kubebuilder:default="30s"
	// +optional
	RefreshInterval metav1.Duration `json:"refreshInterval,omitempty"`

	// MasterKeySecretRef references the Secret holding the master ed25519
	// key for the frontend onionbalance daemon. Required. The Secret MUST
	// contain `hs_ed25519_secret_key` (64 bytes) and `hs_ed25519_public_key`
	// (32 bytes) in the standard Tor binary format — the same shape as a
	// HiddenServiceDir's key files, NOT the onionbalance PEM format.
	//
	// +required
	MasterKeySecretRef MasterKeySecretRef `json:"masterKeySecretRef"`

	// BackendResources is the resource request/limit applied to each
	// backend Tor pod.
	//
	// +optional
	BackendResources *corev1.ResourceRequirements `json:"backendResources,omitempty"`

	// FrontendResources is the resource request/limit applied to the
	// onionbalance frontend pod.
	//
	// +optional
	FrontendResources *corev1.ResourceRequirements `json:"frontendResources,omitempty"`
}

// OnionBalancePolicyStatus reflects acceptance per ancestor Gateway and
// surfaces the current backend-readiness count for ease of operations.
type OnionBalancePolicyStatus struct {
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	// +optional
	Ancestors []gwv1.PolicyAncestorStatus `json:"ancestors,omitempty"`

	// ReadyBackends is the number of backend Tor instances whose
	// descriptors have been observed by the frontend and merged into the
	// published superdescriptor. May be less than spec.replicas during
	// rollout or after a node failure.
	//
	// +kubebuilder:validation:Minimum=0
	// +optional
	ReadyBackends int32 `json:"readyBackends,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:categories={gateway-api,tor-gateway},shortName=obp
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Targets",type=string,JSONPath=`.spec.targetRefs[*].name`
// +kubebuilder:printcolumn:name="Desired",type=integer,JSONPath=`.spec.replicas`
// +kubebuilder:printcolumn:name="Ready",type=integer,JSONPath=`.status.readyBackends`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// OnionBalancePolicy turns a Gateway into a load-balanced hidden service
// behind a master .onion address using the onionbalance daemon.
type OnionBalancePolicy struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec OnionBalancePolicySpec `json:"spec"`

	// +optional
	Status OnionBalancePolicyStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// OnionBalancePolicyList contains a list of OnionBalancePolicy.
type OnionBalancePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []OnionBalancePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OnionBalancePolicy{}, &OnionBalancePolicyList{})
}
