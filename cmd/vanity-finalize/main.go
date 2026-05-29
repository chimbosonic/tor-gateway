/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package main

import (
	"context"
	"flag"
	"fmt"
	"maps"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Command vanity-finalize runs as the second container of the per-Gateway
// vanity Job. It reads the keys mkp224o brute-forced from --workdir and
// updates the pre-created, operator-owned Secret named --secret-name with
// them. The operator then promotes those keys into the canonical key Secret.
func main() {
	var workdir, namespace, secretName string
	flag.StringVar(&workdir, "workdir", "/workdir", "directory mkp224o wrote keys to")
	flag.StringVar(&namespace, "namespace", "", "namespace of the output Secret")
	flag.StringVar(&secretName, "secret-name", "", "name of the pre-created output Secret to update")
	flag.Parse()

	if namespace == "" || secretName == "" {
		fmt.Fprintln(os.Stderr, "vanity-finalize: --namespace and --secret-name are required")
		os.Exit(2)
	}

	data, err := readKeyFiles(workdir)
	if err != nil {
		fatal(err)
	}

	c, err := client.New(ctrl.GetConfigOrDie(), client.Options{})
	if err != nil {
		fatal(err)
	}

	ctx := context.Background()
	sec := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: secretName}, sec); err != nil {
		fatal(err)
	}
	if sec.Data == nil {
		sec.Data = map[string][]byte{}
	}
	maps.Copy(sec.Data, data)
	if err := c.Update(ctx, sec); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "vanity-finalize:", err)
	os.Exit(1)
}
