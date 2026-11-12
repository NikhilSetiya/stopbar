// Package enrich reads prices and balances from the chain to build the policy
// context (CS-131/132): native and ERC-20 balances via eth_getBalance /
// eth_call(balanceOf), and USD prices from on-chain Chainlink feeds. It is the
// production replacement for internal/devstub's static World.
//
// It is stdlib-only on purpose: go-ethereum is edge code confined to
// internal/signer (see CLAUDE.md), so the JSON-RPC client and the small amount
// of ABI encode/decode this needs are hand-written here. The enricher is not in
// the hashing/signing core; it feeds policy, and a missing or stale read is
// marked (price_stale) rather than guessed, so policy fails closed.
package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// RPC is a minimal Ethereum JSON-RPC client over HTTP. It issues only the
// read-only calls the enricher needs (eth_getBalance, eth_call) and never
// sends a transaction or touches a key.
type RPC struct {
	url    string
	client *http.Client
	id     atomic.Uint64
}

// NewRPC returns a client for the JSON-RPC endpoint at url. timeout bounds each
// call (0 uses a 5s default).
func NewRPC(url string, timeout time.Duration) *RPC {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &RPC{url: strings.TrimRight(url, "/"), client: &http.Client{Timeout: timeout}}
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// call issues one JSON-RPC request and returns the raw result.
func (c *RPC) call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: c.id.Add(1), Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rpc %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rpc %s: HTTP %d", method, resp.StatusCode)
	}
	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("rpc %s: decode: %w", method, err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc %s: %s (%d)", method, out.Error.Message, out.Error.Code)
	}
	return out.Result, nil
}

// BalanceAt returns the native balance (wei) of addr at the latest block.
func (c *RPC) BalanceAt(ctx context.Context, addr string) (*big.Int, error) {
	raw, err := c.call(ctx, "eth_getBalance", addr, "latest")
	if err != nil {
		return nil, err
	}
	var hex string
	if err := json.Unmarshal(raw, &hex); err != nil {
		return nil, fmt.Errorf("eth_getBalance: %w", err)
	}
	return hexToInt(hex)
}

// Call executes a read-only eth_call to `to` with calldata `data` (0x-hex) at
// the latest block, returning the raw return bytes.
func (c *RPC) Call(ctx context.Context, to string, data []byte) ([]byte, error) {
	raw, err := c.call(ctx, "eth_call", map[string]string{"to": to, "data": "0x" + bytesToHex(data)}, "latest")
	if err != nil {
		return nil, err
	}
	var hex string
	if err := json.Unmarshal(raw, &hex); err != nil {
		return nil, fmt.Errorf("eth_call: %w", err)
	}
	return hexToBytes(hex)
}
