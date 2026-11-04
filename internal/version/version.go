// Package version exposes build metadata, set via -ldflags at release time.
package version

// Version is overridden at build time: -ldflags "-X github.com/setiyanikhil/stopbar/internal/version.Version=v0.1.0".
var Version = "0.0.0-dev"
