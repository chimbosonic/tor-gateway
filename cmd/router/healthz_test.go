/*
Copyright 2026 Alexis Lowe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthzHandler_OK(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	healthzHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/healthz: got %d want 200", rr.Code)
	}
}
