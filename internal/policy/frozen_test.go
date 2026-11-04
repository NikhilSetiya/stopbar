package policy

import (
	"os"
	"strings"
	"testing"
)

// frozenBankingHash is the AgentDojo pilot bundle frozen in
// research/agentdojo/policies/banking/FREEZE.md. Changing the pack is a new
// pre-registered version, never an edit: this test must not be "fixed" by
// updating the constant.
const frozenBankingHash = "sha256:a974808bc9acb999b332b85c4aea081360919a78f60cc53c1298600abeedd27c"

func TestBankingPackIsFrozen(t *testing.T) {
	b, err := Load(bankingDir)
	if err != nil {
		t.Fatal(err)
	}
	if b.Hash() != frozenBankingHash {
		t.Fatalf("frozen pilot bundle changed: hash %s, frozen %s. Edits after the freeze are a new pre-registered version (see FREEZE.md)", b.Hash(), frozenBankingHash)
	}
	freeze, err := os.ReadFile(bankingDir + "/FREEZE.md")
	if err != nil || !strings.Contains(string(freeze), frozenBankingHash) {
		t.Fatal("FREEZE.md does not record the frozen hash")
	}
}
