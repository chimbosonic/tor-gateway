/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package tor

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VanityJobConfig is the input to VanityJob. All fields are operator-owned;
// only Prefix is sourced (validated) from user input via TorServicePolicy.
type VanityJobConfig struct {
	// JobName is the metadata.name of the generated Job. Convention:
	// "<gateway>-vanity".
	JobName string
	// Namespace is the policy's namespace. The output Secret will be
	// created here.
	Namespace string
	// Prefix is the base32 prefix mkp224o brute-forces against. Must be
	// non-empty and match the base32 alphabet [a-z2-7].
	Prefix string

	// OutputSecretName is the Secret the finalize step writes the
	// resulting hs_ed25519_secret_key / hs_ed25519_public_key / hostname
	// files into. Operator-side reconciliation watches for this Secret to
	// signal Job completion.
	OutputSecretName string

	// ServiceAccountName is the SA the Job pod runs as. The caller is
	// responsible for binding it to a Role that grants create on the
	// single Secret named OutputSecretName.
	ServiceAccountName string

	// Mkp224oImage is the container that runs the mkp224o brute-force.
	Mkp224oImage string
	// FinalizeImage runs the small operator-owned binary that reads the
	// generated keys from the shared volume and creates the output
	// Secret. Expected to be one of the operator's own images.
	FinalizeImage string

	// ActiveDeadline caps how long the Job runs before being killed; this
	// is the "vanity prefix difficulty" guard. Defaults to 1h.
	ActiveDeadline time.Duration

	// Labels merged into the Job and Pod metadata.
	Labels map[string]string
	// Annotations merged into the Pod template.
	Annotations map[string]string

	// Mkp224oResources is the resource request/limit applied to the
	// brute-force container. mkp224o is CPU-bound; defaults are
	// deliberately small so users opt in to higher.
	Mkp224oResources corev1.ResourceRequirements
}

// vanityPrefixPattern is the base32 alphabet Tor uses (lowercase no padding).
var vanityPrefixPattern = regexp.MustCompile(`^[a-z2-7]{1,8}$`)

// VanityJob returns a Job manifest that runs mkp224o to brute-force a
// vanity .onion prefix and writes the resulting keys into a Secret. The
// returned Job is pure data; the caller is responsible for applying it
// to the cluster and binding RBAC.
func VanityJob(cfg VanityJobConfig) (*batchv1.Job, error) {
	if cfg.JobName == "" || cfg.Namespace == "" {
		return nil, errors.New("tor: VanityJobConfig requires JobName and Namespace")
	}
	if !vanityPrefixPattern.MatchString(cfg.Prefix) {
		return nil, fmt.Errorf("tor: invalid vanity prefix %q (need %s)", cfg.Prefix, vanityPrefixPattern)
	}
	if cfg.OutputSecretName == "" {
		return nil, errors.New("tor: VanityJobConfig.OutputSecretName is required")
	}
	if cfg.ServiceAccountName == "" {
		return nil, errors.New("tor: VanityJobConfig.ServiceAccountName is required")
	}
	if cfg.Mkp224oImage == "" || cfg.FinalizeImage == "" {
		return nil, errors.New("tor: VanityJobConfig.Mkp224oImage and FinalizeImage are required")
	}

	deadline := cfg.ActiveDeadline
	if deadline <= 0 {
		deadline = time.Hour
	}
	deadlineSec := int64(deadline.Seconds())

	mkpResources := cfg.Mkp224oResources
	if (mkpResources.Requests == nil) || mkpResources.Requests.Cpu().IsZero() {
		mkpResources.Requests = corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		}
	}
	if (mkpResources.Limits == nil) || mkpResources.Limits.Cpu().IsZero() {
		mkpResources.Limits = corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("2"),
			corev1.ResourceMemory: resource.MustParse("256Mi"),
		}
	}

	labels := mergeLabels(map[string]string{
		"app.kubernetes.io/managed-by": "tor-gateway",
		"app.kubernetes.io/component":  "vanity",
	}, cfg.Labels)

	nonRoot := true
	uidGid := int64(65532)
	podSec := &corev1.PodSecurityContext{
		RunAsNonRoot: &nonRoot,
		RunAsUser:    &uidGid,
		RunAsGroup:   &uidGid,
		FSGroup:      &uidGid,
		SeccompProfile: &corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		},
	}
	allowEsc := false
	readOnlyFS := true
	backoffZero := int32(0)
	ttl := int32(3600)
	containerSec := &corev1.SecurityContext{
		AllowPrivilegeEscalation: &allowEsc,
		ReadOnlyRootFilesystem:   &readOnlyFS,
		RunAsNonRoot:             &nonRoot,
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
	}

	const workdir = "/workdir"

	job := &batchv1.Job{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Job",
			APIVersion: "batch/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cfg.JobName,
			Namespace: cfg.Namespace,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            &backoffZero,
			ActiveDeadlineSeconds:   &deadlineSec,
			TTLSecondsAfterFinished: &ttl,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      labels,
					Annotations: cfg.Annotations,
				},
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyNever,
					ServiceAccountName: cfg.ServiceAccountName,
					SecurityContext:    podSec,
					Volumes: []corev1.Volume{{
						Name:         "workdir",
						VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
					}},
					InitContainers: []corev1.Container{{
						Name:            "mkp224o",
						Image:           cfg.Mkp224oImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args: []string{
							"-d", workdir,
							"-n", "1",
							"-q",
							cfg.Prefix,
						},
						Resources:       mkpResources,
						SecurityContext: containerSec,
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "workdir",
							MountPath: workdir,
						}},
					}},
					Containers: []corev1.Container{{
						Name:            "finalize",
						Image:           cfg.FinalizeImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args: []string{
							"--workdir", workdir,
							"--namespace", cfg.Namespace,
							"--secret-name", cfg.OutputSecretName,
						},
						SecurityContext: containerSec,
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "workdir",
							MountPath: workdir,
							ReadOnly:  true,
						}},
					}},
				},
			},
		},
	}
	return job, nil
}

func mergeLabels(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	maps.Copy(out, base)
	maps.Copy(out, extra)
	return out
}
