// Command countersignd is the Countersign policy service / sidecar.
// The HTTP gateway lands in CS-101; this binary only reports its version for now.
package main

import (
	"fmt"

	"github.com/setiyanikhil/countersign/internal/version"
)

func main() { fmt.Println("countersignd", version.Version, "- gateway not implemented yet (CS-101)") }
