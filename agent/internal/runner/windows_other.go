//go:build !windows

package runner

import (
	"context"

	"aegis/agent/internal/config"
	"aegis/agent/internal/parsers"
)

// pollWindows is unavailable outside Windows; the source reports a clear error status.
func (r *Runner) pollWindows(_ context.Context, src config.Source, _ parsers.Parser) bool {
	r.setStatus(src.Name, func(s *SourceStatus) {
		s.Status, s.Error = "error", "windows_eventlog is only available on Windows"
	})
	return false
}
