/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// BuildVanityServiceAccount emits the ServiceAccount the vanity harvest Job
// runs under.
func BuildVanityServiceAccount(gw *gwv1.Gateway, scheme *runtime.Scheme) (*corev1.ServiceAccount, error) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      VanityRBACName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    ChildLabels(gw.Name),
		},
	}
	if err := controllerutil.SetControllerReference(gw, sa, scheme); err != nil {
		return nil, err
	}
	return sa, nil
}

// BuildVanityRole grants the harvest Job get/update/patch on the single
// pre-created output Secret. RBAC resourceNames constrains these verbs (but
// NOT create/list/delete), which is why the controller pre-creates the
// Secret and the finalize step updates it in place.
func BuildVanityRole(gw *gwv1.Gateway, scheme *runtime.Scheme) (*rbacv1.Role, error) {
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      VanityRBACName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    ChildLabels(gw.Name),
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			ResourceNames: []string{VanityOutSecretName(gw.Name)},
			Verbs:         []string{"get", "update", "patch"},
		}},
	}
	if err := controllerutil.SetControllerReference(gw, role, scheme); err != nil {
		return nil, err
	}
	return role, nil
}

// BuildVanityRoleBinding binds the vanity ServiceAccount to the vanity Role.
func BuildVanityRoleBinding(gw *gwv1.Gateway, scheme *runtime.Scheme) (*rbacv1.RoleBinding, error) {
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      VanityRBACName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    ChildLabels(gw.Name),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     VanityRBACName(gw.Name),
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      VanityRBACName(gw.Name),
			Namespace: gw.Namespace,
		}},
	}
	if err := controllerutil.SetControllerReference(gw, rb, scheme); err != nil {
		return nil, err
	}
	return rb, nil
}

// BuildVanityOutSecret emits the empty, operator-owned Secret the harvest Job
// updates with the keys mkp224o produces.
func BuildVanityOutSecret(gw *gwv1.Gateway, scheme *runtime.Scheme) (*corev1.Secret, error) {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      VanityOutSecretName(gw.Name),
			Namespace: gw.Namespace,
			Labels:    ChildLabels(gw.Name),
		},
		Type: corev1.SecretTypeOpaque,
	}
	if err := controllerutil.SetControllerReference(gw, s, scheme); err != nil {
		return nil, err
	}
	return s, nil
}
