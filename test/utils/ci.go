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

package utils

import (
	"fmt"
	"os"
)

// CIWarning emits a GitHub Actions warning annotation (and a plain line for
// local runs). Workflow commands are parsed from any `run:` step's stdout,
// which includes `go test` output.
func CIWarning(format string, a ...any) {
	_, _ = fmt.Fprintf(os.Stdout, "::warning::"+format+"\n", a...)
}

// StepSummary appends a line to the GitHub Actions step summary when
// available; always echoes to stdout so local runs see it too.
func StepSummary(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	_, _ = fmt.Fprintln(os.Stdout, "[summary] "+line)
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintln(f, line)
}
