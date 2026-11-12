package signer

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/NikhilSetiya/stopbar/internal/decode/evm"
	"github.com/NikhilSetiya/stopbar/internal/enrich"
)

// The decoder is stdlib-only and can't compute keccak-256, so its selector
// table is checked here, where go-ethereum is allowed.
func TestDecoderSelectorsMatchKeccak(t *testing.T) {
	for sel, sig := range evm.Signatures {
		if got := hex.EncodeToString(crypto.Keccak256([]byte(sig))[:4]); got != sel {
			t.Errorf("%s: selector %s, keccak says %s", sig, sel, got)
		}
	}
}

// The enricher (internal/enrich) is likewise stdlib-only; its balanceOf /
// decimals / latestRoundData selectors are checked here too.
func TestEnrichSelectorsMatchKeccak(t *testing.T) {
	for sel, sig := range enrich.Signatures {
		if got := hex.EncodeToString(crypto.Keccak256([]byte(sig))[:4]); got != sel {
			t.Errorf("%s: selector %s, keccak says %s", sig, sel, got)
		}
	}
}
