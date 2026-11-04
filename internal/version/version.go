// Package version exposes build metadata, set via -ldflags at release time.
package version

// Version is the source release; builds may override it with
// -ldflags "-X github.com/NikhilSetiya/stopbar/internal/version.Version=…".
var Version = "0.1.0-alpha"
