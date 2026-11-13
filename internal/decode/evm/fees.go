package evm

import (
	"fmt"
	"math/big"
)

// FeeLimits are the fee terms above which a transaction is flagged
// excessive_fee: it could burn far more in gas than any normal transaction
// on that chain (the fee-drain pattern, CS-2026-0007). Values are in the
// chain's native unit (wei) and gas units.
type FeeLimits struct {
	Name           string
	MaxFeePerGas   *big.Int // wei per gas
	MaxGasLimit    uint64
	MaxTotalFeeWei *big.Int // gas_limit × max_fee_per_gas
}

func gwei(n int64) *big.Int { return new(big.Int).Mul(big.NewInt(n), big.NewInt(1_000_000_000)) }

// milli is n / 1000 of the native unit (10^15 wei each).
func milli(n int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(n), big.NewInt(1_000_000_000_000_000))
}

// Chains lists the networks the decoder accepts. A transaction for any other
// chain is not decoded (fail closed): fee sanity can't be judged without
// knowing the chain. Thresholds sit well above each chain's observed spikes,
// so they catch drains rather than busy blocks:
//   - Ethereum: 1,000 gwei; 0.25 ETH total (a 1M-gas call at 250 gwei).
//   - L2s (Base, Optimism, Arbitrum): fees are cents; 50 gwei, 0.02 ETH total.
//     Arbitrum's gas limits include L1 data cost, hence the higher gas cap.
//   - Polygon: gas is priced in POL and routinely spikes into the thousands of
//     gwei; 10,000 gwei, 50 POL total.
//   - BNB Chain: 100 gwei, 0.1 BNB total.
//   - Test chains (Sepolia, Anvil) use Ethereum's limits, so fixtures behave
//     as on mainnet.
var Chains = map[uint64]FeeLimits{
	1:        {"ethereum", gwei(1000), 30_000_000, milli(250)},
	10:       {"optimism", gwei(50), 30_000_000, milli(20)},
	56:       {"bnb", gwei(100), 30_000_000, milli(100)},
	137:      {"polygon", gwei(10_000), 30_000_000, new(big.Int).Mul(big.NewInt(50), milli(1000))},
	8453:     {"base", gwei(50), 30_000_000, milli(20)},
	84532:    {"base-sepolia", gwei(50), 30_000_000, milli(20)}, // Base's L2 limits (make demo-testnet)
	42161:    {"arbitrum", gwei(50), 100_000_000, milli(20)},
	11155111: {"sepolia", gwei(1000), 30_000_000, milli(250)},
	31337:    {"anvil", gwei(1000), 30_000_000, milli(250)},
}

// excessiveFee reports whether the fee terms exceed the chain's limits.
func excessiveFee(chainID uint64, gasLimit, maxFeePerGas *big.Int) (bool, string, error) {
	l, ok := Chains[chainID]
	if !ok {
		return false, "", fmt.Errorf("chain %d is not supported (no fee limits)", chainID)
	}
	total := new(big.Int).Mul(gasLimit, maxFeePerGas)
	switch {
	case maxFeePerGas.Cmp(l.MaxFeePerGas) > 0:
		return true, fmt.Sprintf("max fee per gas %s wei exceeds the %s limit %s", maxFeePerGas, l.Name, l.MaxFeePerGas), nil
	case !gasLimit.IsUint64() || gasLimit.Uint64() > l.MaxGasLimit:
		return true, fmt.Sprintf("gas limit %s exceeds the %s limit %d", gasLimit, l.Name, l.MaxGasLimit), nil
	case total.Cmp(l.MaxTotalFeeWei) > 0:
		return true, fmt.Sprintf("max total fee %s wei exceeds the %s limit %s", total, l.Name, l.MaxTotalFeeWei), nil
	}
	return false, "", nil
}
