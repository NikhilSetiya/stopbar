package signer

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/NikhilSetiya/stopbar/internal/model"
)

func TestDelegatedTo(t *testing.T) {
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	code := append([]byte{0xef, 0x01, 0x00}, addr.Bytes()...)
	if got, ok := DelegatedTo(code); !ok || got != addr {
		t.Fatalf("delegation not detected: %v %v", got, ok)
	}
	for _, c := range [][]byte{nil, {}, []byte("not a 23-byte delegation!!"), append([]byte{0xef, 0x01, 0x01}, addr.Bytes()...), {0xef, 0x01, 0x00}} {
		if _, ok := DelegatedTo(c); ok {
			t.Fatalf("false positive on %x", c)
		}
	}
}

// The adapter refuses to sign for a wallet carrying unexpected EIP-7702
// delegation code, admits a vetted delegate, and fails closed on a read error.
func TestSignRefusesDelegatedWallet(t *testing.T) {
	delegate := common.HexToAddress("0x2222222222222222222222222222222222222222")
	delegated := append([]byte{0xef, 0x01, 0x00}, delegate.Bytes()...)
	for name, tc := range map[string]struct {
		code     []byte
		codeErr  error
		expected map[common.Address]bool
		refused  bool
	}{
		"codeless EOA signs":            {nil, nil, nil, false},
		"unexpected delegation refused": {delegated, nil, nil, true},
		"vetted delegate signs":         {delegated, nil, map[common.Address]bool{delegate: true}, false},
		"code read error fails closed":  {nil, errors.New("rpc down"), nil, true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			a := action()
			r.adapter.codeAt = func(context.Context, common.Address) ([]byte, error) { return tc.code, tc.codeErr }
			r.adapter.expected = tc.expected
			_, _, err := r.adapter.SignTx(context.Background(), r.token(t, a, model.Allow), a)
			if tc.refused && !errors.Is(err, ErrDelegatedWallet) {
				t.Fatalf("want ErrDelegatedWallet, got %v", err)
			}
			if !tc.refused && err != nil {
				t.Fatalf("want a signature, got %v", err)
			}
		})
	}
}
