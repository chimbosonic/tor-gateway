/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package router

import (
	"fmt"
	"net/url"
)

// ClusterResolver returns a BackendResolver that maps a Backend to its
// in-cluster Service DNS URL (http://<name>.<namespace>.svc:<port>). It
// returns ok=false for any backend missing a name, namespace, or port.
func ClusterResolver() BackendResolver {
	return func(b Backend) (*url.URL, bool) {
		if b.Name == "" || b.Namespace == "" || b.Port == 0 {
			return nil, false
		}
		u := &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("%s.%s.svc:%d", b.Name, b.Namespace, b.Port),
		}
		return u, true
	}
}
