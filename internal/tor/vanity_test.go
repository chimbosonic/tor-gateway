/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package tor

import (
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func validVanityCfg() VanityJobConfig {
	return VanityJobConfig{
		JobName:            "blog-vanity",
		Namespace:          "default",
		Prefix:             "blog",
		OutputSecretName:   "blog-tor-keys",
		ServiceAccountName: "tor-gateway-vanity",
		Mkp224oImage:       "ghcr.io/chimbosonic/mkp224o:0.0.1",
		FinalizeImage:      "ghcr.io/chimbosonic/tor-gateway-vanity-finalize:0.0.1",
	}
}

func TestVanityJob_HappyPath(t *testing.T) {
	job, err := VanityJob(validVanityCfg())
	if err != nil {
		t.Fatal(err)
	}
	if job.Name != "blog-vanity" || job.Namespace != "default" {
		t.Fatalf("wrong meta: %s/%s", job.Namespace, job.Name)
	}
	if *job.Spec.BackoffLimit != 0 {
		t.Fatalf("backoffLimit = %d, want 0 (vanity is best-effort)", *job.Spec.BackoffLimit)
	}
	if d := *job.Spec.ActiveDeadlineSeconds; d != int64(time.Hour.Seconds()) {
		t.Fatalf("default deadline = %d, want %d", d, int64(time.Hour.Seconds()))
	}
	pod := job.Spec.Template.Spec
	if pod.RestartPolicy != corev1.RestartPolicyNever {
		t.Fatalf("restartPolicy = %q, want Never", pod.RestartPolicy)
	}
	if pod.ServiceAccountName != "tor-gateway-vanity" {
		t.Fatalf("wrong SA: %s", pod.ServiceAccountName)
	}
	if len(pod.InitContainers) != 1 || pod.InitContainers[0].Name != "mkp224o" {
		t.Fatalf("expected mkp224o init container, got %+v", pod.InitContainers)
	}
	if len(pod.Containers) != 1 || pod.Containers[0].Name != "finalize" {
		t.Fatalf("expected finalize container, got %+v", pod.Containers)
	}

	// Prefix is passed to mkp224o.
	wantArgs := []string{"-d", "/workdir", "-n", "1", "-q", "blog"}
	if !sliceEqual(pod.InitContainers[0].Args, wantArgs) {
		t.Fatalf("mkp224o args = %v, want %v", pod.InitContainers[0].Args, wantArgs)
	}

	// Finalize container gets the namespace + secret name from the operator.
	wantFin := []string{"--workdir", "/workdir", "--namespace", "default", "--secret-name", "blog-tor-keys"}
	if !sliceEqual(pod.Containers[0].Args, wantFin) {
		t.Fatalf("finalize args = %v, want %v", pod.Containers[0].Args, wantFin)
	}
}

func TestVanityJob_PodHardening(t *testing.T) {
	job, err := VanityJob(validVanityCfg())
	if err != nil {
		t.Fatal(err)
	}
	pod := job.Spec.Template.Spec

	if pod.SecurityContext == nil ||
		pod.SecurityContext.RunAsNonRoot == nil ||
		!*pod.SecurityContext.RunAsNonRoot {
		t.Fatal("pod must be runAsNonRoot=true")
	}
	if pod.SecurityContext.SeccompProfile == nil ||
		pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatal("pod must use RuntimeDefault seccomp profile")
	}

	for _, c := range append(pod.InitContainers, pod.Containers...) {
		if c.SecurityContext == nil {
			t.Fatalf("container %s has no SecurityContext", c.Name)
		}
		if c.SecurityContext.AllowPrivilegeEscalation == nil ||
			*c.SecurityContext.AllowPrivilegeEscalation {
			t.Fatalf("container %s allows privilege escalation", c.Name)
		}
		if c.SecurityContext.ReadOnlyRootFilesystem == nil ||
			!*c.SecurityContext.ReadOnlyRootFilesystem {
			t.Fatalf("container %s root FS not read-only", c.Name)
		}
		if c.SecurityContext.Capabilities == nil ||
			!hasCapability(c.SecurityContext.Capabilities.Drop, "ALL") {
			t.Fatalf("container %s does not drop ALL caps", c.Name)
		}
	}
}

func TestVanityJob_RejectsBadInputs(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*VanityJobConfig)
		want   string
	}{
		{"empty job name", func(c *VanityJobConfig) { c.JobName = "" }, "JobName"},
		{"empty namespace", func(c *VanityJobConfig) { c.Namespace = "" }, "Namespace"},
		{"uppercase prefix", func(c *VanityJobConfig) { c.Prefix = "BLOG" }, "invalid vanity prefix"},
		{"digit-8 in prefix", func(c *VanityJobConfig) { c.Prefix = "abc8" }, "invalid vanity prefix"},
		{"empty prefix", func(c *VanityJobConfig) { c.Prefix = "" }, "invalid vanity prefix"},
		{"too long prefix", func(c *VanityJobConfig) { c.Prefix = "abcdefghi" }, "invalid vanity prefix"},
		{"empty output secret", func(c *VanityJobConfig) { c.OutputSecretName = "" }, "OutputSecretName"},
		{"empty SA", func(c *VanityJobConfig) { c.ServiceAccountName = "" }, "ServiceAccountName"},
		{"empty mkp224o image", func(c *VanityJobConfig) { c.Mkp224oImage = "" }, "Mkp224oImage"},
		{"empty finalize image", func(c *VanityJobConfig) { c.FinalizeImage = "" }, "FinalizeImage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validVanityCfg()
			tc.mutate(&c)
			_, err := VanityJob(c)
			if err == nil {
				t.Fatal("expected error")
			}
			if !contains(err.Error(), tc.want) {
				t.Fatalf("error %q missing %q", err, tc.want)
			}
		})
	}
}

func TestVanityJob_CustomDeadline(t *testing.T) {
	cfg := validVanityCfg()
	cfg.ActiveDeadline = 15 * time.Minute
	job, err := VanityJob(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := *job.Spec.ActiveDeadlineSeconds; got != 900 {
		t.Fatalf("ActiveDeadlineSeconds = %d, want 900", got)
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasCapability(list []corev1.Capability, want corev1.Capability) bool {
	return slices.Contains(list, want)
}
