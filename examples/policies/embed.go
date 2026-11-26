// Package policies embeds the agent-wallet starter pack, so `stopbar init`
// writes this exact bundle without a repo checkout (one copy, never forked).
package policies

import "embed"

// FS holds the bundle files: the policies and their schema.
//
//go:embed agent-wallet.cedar stopbar.cedarschema
var FS embed.FS
