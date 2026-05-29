/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"errors"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/chimbosonic/tor-gateway/internal/tor"
)

// Sentinels returned by the harvest path. Reconcile maps them to status
// conditions instead of treating them as hard errors.
var (
	errHarvestPending = errors.New("vanity harvest pending")
	errHarvestFailed  = errors.New("vanity harvest failed")
	// errAwaitingVanityPolicy is returned for a keyless Gateway that opted in
	// (await-vanity annotation) but has no matching vanityPrefix policy yet.
	errAwaitingVanityPolicy = errors.New("awaiting vanity policy")
)

// Programmed=False condition reasons for the harvest lifecycle.
const (
	ReasonVanityHarvestInProgress = "VanityHarvestInProgress"
	ReasonVanityHarvestFailed     = "VanityHarvestFailed"
	ReasonAwaitingVanityPolicy    = "AwaitingVanityPolicy"
)

// runVanityHarvest drives the creation-time vanity flow. It returns
// (secret, keypair, nil) once the harvested key has been promoted into
// <gw>-keys, errHarvestPending while the Job is still running, or
// errHarvestFailed when the Job exceeded its deadline.
func (r *GatewayReconciler) runVanityHarvest(
	ctx context.Context,
	gw *gwv1.Gateway,
	prefix string,
) (*corev1.Secret, *tor.KeyPair, error) {
	// Already failed for this exact prefix: do not relaunch (avoids an
	// hourly loop once the Job's TTL GCs it).
	if gw.Annotations[vanityFailedAnnotation] == prefix {
		return nil, nil, errHarvestFailed
	}

	if err := r.ensureVanityRBAC(ctx, gw); err != nil {
		return nil, nil, err
	}
	if err := r.ensureVanityOutSecret(ctx, gw); err != nil {
		return nil, nil, err
	}

	job := &batchv1.Job{}
	jobKey := client.ObjectKey{Namespace: gw.Namespace, Name: VanityRBACName(gw.Name)}
	err := r.Get(ctx, jobKey, job)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.createVanityJob(ctx, gw, prefix); err != nil {
			return nil, nil, err
		}
		r.event(gw, corev1.EventTypeNormal, "VanityHarvestStarted",
			fmt.Sprintf("harvesting vanity .onion with prefix %q", prefix))
		return nil, nil, errHarvestPending
	case err != nil:
		return nil, nil, err
	}

	// A Job exists. If it targets a stale prefix, delete it so the next
	// reconcile launches a fresh one, and clear any recorded failure.
	if job.Labels[vanityPrefixLabel] != prefix {
		if err := r.deleteVanityJob(ctx, job); err != nil {
			return nil, nil, err
		}
		if err := r.clearVanityFailed(ctx, gw); err != nil {
			return nil, nil, err
		}
		return nil, nil, errHarvestPending
	}

	out := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: VanityOutSecretName(gw.Name)}, out); err != nil {
		return nil, nil, err
	}
	if vanityOutPopulated(out) {
		return r.promoteVanityKey(ctx, gw, out, job)
	}

	if jobFailed(job) {
		if err := r.markVanityFailed(ctx, gw, prefix); err != nil {
			return nil, nil, err
		}
		r.event(gw, corev1.EventTypeWarning, "VanityHarvestFailed",
			fmt.Sprintf("vanity harvest for prefix %q exceeded its deadline; choose a shorter prefix", prefix))
		return nil, nil, errHarvestFailed
	}

	return nil, nil, errHarvestPending
}

// createVanityJob builds and creates the per-Gateway harvest Job.
func (r *GatewayReconciler) createVanityJob(ctx context.Context, gw *gwv1.Gateway, prefix string) error {
	job, err := tor.VanityJob(tor.VanityJobConfig{
		JobName:            VanityRBACName(gw.Name),
		Namespace:          gw.Namespace,
		Prefix:             prefix,
		OutputSecretName:   VanityOutSecretName(gw.Name),
		ServiceAccountName: VanityRBACName(gw.Name),
		Mkp224oImage:       r.Images.Mkp224o,
		FinalizeImage:      r.Images.VanityFinalize,
		ActiveDeadline:     r.VanityDeadline,
		Labels: map[string]string{
			gatewayLabelKey:   gw.Name,
			vanityPrefixLabel: prefix,
		},
	})
	if err != nil {
		return fmt.Errorf("build vanity job: %w", err)
	}
	if err := controllerutil.SetControllerReference(gw, job, r.Scheme); err != nil {
		return err
	}
	return r.Create(ctx, job)
}

// promoteVanityKey parses the harvested key, creates the canonical key
// Secret, and cleans up the throwaway Secret + Job.
func (r *GatewayReconciler) promoteVanityKey(
	ctx context.Context,
	gw *gwv1.Gateway,
	out *corev1.Secret,
	job *batchv1.Job,
) (*corev1.Secret, *tor.KeyPair, error) {
	kp, err := tor.ParseFiles(out.Data[tor.FileSecretKeyName], out.Data[tor.FilePublicKeyName])
	if err != nil {
		return nil, nil, fmt.Errorf("parse harvested key: %w", err)
	}
	secret, err := BuildKeySecret(gw, kp, r.Scheme)
	if err != nil {
		return nil, nil, err
	}
	if err := r.Create(ctx, secret); err != nil {
		return nil, nil, err
	}
	// Best-effort cleanup; the canonical key now exists, so reconcile must
	// proceed regardless of cleanup hiccups.
	_ = r.Delete(ctx, out)
	_ = r.deleteVanityJob(ctx, job)
	_ = r.clearVanityFailed(ctx, gw)
	return secret, kp, nil
}

func (r *GatewayReconciler) ensureVanityRBAC(ctx context.Context, gw *gwv1.Gateway) error {
	sa, err := BuildVanityServiceAccount(gw, r.Scheme)
	if err != nil {
		return err
	}
	cur := &corev1.ServiceAccount{}
	cur.Name, cur.Namespace = sa.Name, sa.Namespace
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, cur, func() error {
		cur.Labels = sa.Labels
		cur.OwnerReferences = sa.OwnerReferences
		return nil
	}); err != nil {
		return err
	}

	role, err := BuildVanityRole(gw, r.Scheme)
	if err != nil {
		return err
	}
	curRole := &rbacv1.Role{}
	curRole.Name, curRole.Namespace = role.Name, role.Namespace
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, curRole, func() error {
		curRole.Labels = role.Labels
		curRole.Rules = role.Rules
		curRole.OwnerReferences = role.OwnerReferences
		return nil
	}); err != nil {
		return err
	}

	rb, err := BuildVanityRoleBinding(gw, r.Scheme)
	if err != nil {
		return err
	}
	curRB := &rbacv1.RoleBinding{}
	curRB.Name, curRB.Namespace = rb.Name, rb.Namespace
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, curRB, func() error {
		curRB.Labels = rb.Labels
		curRB.RoleRef = rb.RoleRef
		curRB.Subjects = rb.Subjects
		curRB.OwnerReferences = rb.OwnerReferences
		return nil
	})
	return err
}

// ensureVanityOutSecret creates the empty output Secret if absent. It never
// updates an existing one — the finalize container owns its Data.
func (r *GatewayReconciler) ensureVanityOutSecret(ctx context.Context, gw *gwv1.Gateway) error {
	cur := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: VanityOutSecretName(gw.Name)}, cur)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	desired, err := BuildVanityOutSecret(gw, r.Scheme)
	if err != nil {
		return err
	}
	return r.Create(ctx, desired)
}

func (r *GatewayReconciler) deleteVanityJob(ctx context.Context, job *batchv1.Job) error {
	policy := metav1.DeletePropagationBackground
	if err := r.Delete(ctx, job, client.PropagationPolicy(policy)); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

func (r *GatewayReconciler) markVanityFailed(ctx context.Context, gw *gwv1.Gateway, prefix string) error {
	if gw.Annotations[vanityFailedAnnotation] == prefix {
		return nil
	}
	patch := client.MergeFrom(gw.DeepCopy())
	if gw.Annotations == nil {
		gw.Annotations = map[string]string{}
	}
	gw.Annotations[vanityFailedAnnotation] = prefix
	return r.Patch(ctx, gw, patch)
}

func (r *GatewayReconciler) clearVanityFailed(ctx context.Context, gw *gwv1.Gateway) error {
	if _, ok := gw.Annotations[vanityFailedAnnotation]; !ok {
		return nil
	}
	patch := client.MergeFrom(gw.DeepCopy())
	delete(gw.Annotations, vanityFailedAnnotation)
	return r.Patch(ctx, gw, patch)
}

// vanityOutPopulated reports whether the finalize step has written both key
// files (of the expected on-disk sizes) into the output Secret.
func vanityOutPopulated(s *corev1.Secret) bool {
	return len(s.Data[tor.FileSecretKeyName]) == tor.SecretKeyFileSize &&
		len(s.Data[tor.FilePublicKeyName]) == tor.PublicKeyFileSize
}

// jobFailed reports whether a Job has a JobFailed=True condition (set by the
// Job controller on deadline-exceeded or backoff exhaustion).
func jobFailed(job *batchv1.Job) bool {
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// setProgrammingCondition writes Accepted=True + Programmed=False(reason) for
// a Gateway whose key is not yet available (harvest in progress or failed).
func (r *GatewayReconciler) setProgrammingCondition(ctx context.Context, gw *gwv1.Gateway, reason, message string) error {
	conds := []metav1.Condition{
		{
			Type:               string(gwv1.GatewayConditionAccepted),
			Status:             metav1.ConditionTrue,
			Reason:             string(gwv1.GatewayReasonAccepted),
			Message:            "Gateway accepted by tor-gateway",
			ObservedGeneration: gw.Generation,
			LastTransitionTime: metav1.Now(),
		},
		{
			Type:               string(gwv1.GatewayConditionProgrammed),
			Status:             metav1.ConditionFalse,
			Reason:             reason,
			Message:            message,
			ObservedGeneration: gw.Generation,
			LastTransitionTime: metav1.Now(),
		},
	}
	changed := false
	for _, c := range conds {
		if setCondition(&gw.Status.Conditions, c) {
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return r.Status().Update(ctx, gw)
}
