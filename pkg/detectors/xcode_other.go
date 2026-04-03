//go:build !darwin

package detectors

import (
	"github.com/securient/ideviewer-oss/pkg/scanner"
)

// XcodeDetector is a no-op on non-macOS platforms.
type XcodeDetector struct{}

func (d *XcodeDetector) Name() string { return "xcode" }

func (d *XcodeDetector) Detect() ([]scanner.IDE, error) {
	return nil, nil
}
