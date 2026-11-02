// Command countersign is the Countersign CLI (policy test, audit verify, corpus replay).
package main

import (
	"fmt"

	"github.com/setiyanikhil/countersign/internal/version"
)

func main() { fmt.Println("countersign", version.Version) }
