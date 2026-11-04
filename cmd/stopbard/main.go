// Command stopbard is the Stopbar policy service / sidecar.
// The HTTP gateway lands in CS-101; this binary only reports its version for now.
package main

import (
	"fmt"

	"github.com/NikhilSetiya/stopbar/internal/version"
)

func main() { fmt.Println("stopbard", version.Version, "- gateway not implemented yet (CS-101)") }
