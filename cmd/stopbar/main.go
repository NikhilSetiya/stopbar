// Command stopbar is the Stopbar CLI (policy test, audit verify, corpus replay).
package main

import (
	"fmt"

	"github.com/setiyanikhil/stopbar/internal/version"
)

func main() { fmt.Println("stopbar", version.Version) }
