package evm

// Selectors the decoder understands. Each carries its canonical signature;
// internal/signer's TestDecoderSelectorsMatchKeccak recomputes every one with
// keccak-256 (go-ethereum is allowed there, not here), so none of these hex
// values is taken on trust.
const (
	// ERC-20 (approve and transferFrom share their encoding with ERC-721)
	selTransfer          = "a9059cbb"
	selApprove           = "095ea7b3"
	selTransferFrom      = "23b872dd"
	selIncreaseAllowance = "39509351"
	selPermit2612        = "d505accf"
	// ERC-721 / ERC-1155
	selSafeTransferFrom721     = "42842e0e"
	selSafeTransferFrom721Data = "b88d4fde"
	selSetApprovalForAll       = "a22cb465"
	selSafeTransferFrom1155    = "f242432a"
	selSafeBatchTransfer1155   = "2eb2c2d6"
	// Permit2
	selP2Approve      = "87517c45"
	selP2PermitSingle = "2b67b570"
	selP2PermitBatch  = "2a2d80d1"
	selP2TransferFrom = "36c78516"
	// Multicall: Uniswap-style (delegatecall to self) and Multicall3
	selMulticall          = "ac9650d8"
	selMulticallDeadline  = "5ae401dc"
	selMulticallPrevBlock = "1f0464d1"
	selAggregate          = "252dba42"
	selTryAggregate       = "bce38bd7"
	selAggregate3         = "82ad56cb"
	selAggregate3Value    = "174dea71"
	// Safe
	selExecTransaction       = "6a761202"
	selMultiSend             = "8d80ff0a"
	selChangeMasterCopy      = "7de7edef"
	selSetFallbackHandler    = "f08a0323"
	selAddOwnerWithThreshold = "0d582f13"
	selRemoveOwner           = "f8dc5dd9"
	selSwapOwner             = "e318b52b"
	selChangeThreshold       = "694e80c3"
	selEnableModule          = "610b5925"
	selSetGuard              = "e19a9dd9"
	// Proxies
	selUpgradeTo        = "3659cfe6"
	selUpgradeToAndCall = "4f1ef286"
	// Uniswap V2 router
	selV2SwapExactTokensForTokens    = "38ed1739"
	selV2SwapExactETHForTokens       = "7ff36ab5"
	selV2SwapExactTokensForETH       = "18cbafe5"
	selV2SwapTokensForExactTokens    = "8803dbee"
	selV2SwapTokensForExactETH       = "4a25d94a"
	selV2SwapETHForExactTokens       = "fb3bdb41"
	selV2SwapExactTokensForTokensFOT = "5c11d795"
	selV2SwapExactETHForTokensFOT    = "b6f9de95"
	selV2SwapExactTokensForETHFOT    = "791ac947"
	// Uniswap V3 SwapRouter (with deadline) and SwapRouter02 (without)
	selV3ExactInputSingle          = "414bf389"
	selV3ExactInput                = "c04b8d59"
	selV3ExactOutputSingle         = "db3e2198"
	selV3ExactOutput               = "f28c0498"
	selR02ExactInputSingle         = "04e45aaf"
	selR02ExactInput               = "b858183f"
	selR02ExactOutputSingle        = "5023b4df"
	selR02ExactOutput              = "09b81346"
	selR02SwapExactTokensForTokens = "472b43f3"
	selR02SwapTokensForExactTokens = "42712a67"
	// Uniswap Universal Router
	selURExecute           = "3593564c"
	selURExecuteNoDeadline = "24856bc3"
)

// Signatures maps each selector to its canonical signature (for the keccak
// cross-check and for rendering).
var Signatures = map[string]string{
	selTransfer:                      "transfer(address,uint256)",
	selApprove:                       "approve(address,uint256)",
	selTransferFrom:                  "transferFrom(address,address,uint256)",
	selIncreaseAllowance:             "increaseAllowance(address,uint256)",
	selPermit2612:                    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
	selSafeTransferFrom721:           "safeTransferFrom(address,address,uint256)",
	selSafeTransferFrom721Data:       "safeTransferFrom(address,address,uint256,bytes)",
	selSetApprovalForAll:             "setApprovalForAll(address,bool)",
	selSafeTransferFrom1155:          "safeTransferFrom(address,address,uint256,uint256,bytes)",
	selSafeBatchTransfer1155:         "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
	selP2Approve:                     "approve(address,address,uint160,uint48)",
	selP2PermitSingle:                "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
	selP2PermitBatch:                 "permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)",
	selP2TransferFrom:                "transferFrom(address,address,uint160,address)",
	selMulticall:                     "multicall(bytes[])",
	selMulticallDeadline:             "multicall(uint256,bytes[])",
	selMulticallPrevBlock:            "multicall(bytes32,bytes[])",
	selAggregate:                     "aggregate((address,bytes)[])",
	selTryAggregate:                  "tryAggregate(bool,(address,bytes)[])",
	selAggregate3:                    "aggregate3((address,bool,bytes)[])",
	selAggregate3Value:               "aggregate3Value((address,bool,uint256,bytes)[])",
	selExecTransaction:               "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
	selMultiSend:                     "multiSend(bytes)",
	selChangeMasterCopy:              "changeMasterCopy(address)",
	selSetFallbackHandler:            "setFallbackHandler(address)",
	selAddOwnerWithThreshold:         "addOwnerWithThreshold(address,uint256)",
	selRemoveOwner:                   "removeOwner(address,address,uint256)",
	selSwapOwner:                     "swapOwner(address,address,address)",
	selChangeThreshold:               "changeThreshold(uint256)",
	selEnableModule:                  "enableModule(address)",
	selSetGuard:                      "setGuard(address)",
	selUpgradeTo:                     "upgradeTo(address)",
	selUpgradeToAndCall:              "upgradeToAndCall(address,bytes)",
	selV2SwapExactTokensForTokens:    "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
	selV2SwapExactETHForTokens:       "swapExactETHForTokens(uint256,address[],address,uint256)",
	selV2SwapExactTokensForETH:       "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
	selV2SwapTokensForExactTokens:    "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)",
	selV2SwapTokensForExactETH:       "swapTokensForExactETH(uint256,uint256,address[],address,uint256)",
	selV2SwapETHForExactTokens:       "swapETHForExactTokens(uint256,address[],address,uint256)",
	selV2SwapExactTokensForTokensFOT: "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
	selV2SwapExactETHForTokensFOT:    "swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)",
	selV2SwapExactTokensForETHFOT:    "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
	selV3ExactInputSingle:            "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
	selV3ExactInput:                  "exactInput((bytes,address,uint256,uint256,uint256))",
	selV3ExactOutputSingle:           "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
	selV3ExactOutput:                 "exactOutput((bytes,address,uint256,uint256,uint256))",
	selR02ExactInputSingle:           "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
	selR02ExactInput:                 "exactInput((bytes,address,uint256,uint256))",
	selR02ExactOutputSingle:          "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))",
	selR02ExactOutput:                "exactOutput((bytes,address,uint256,uint256))",
	selR02SwapExactTokensForTokens:   "swapExactTokensForTokens(uint256,uint256,address[],address)",
	selR02SwapTokensForExactTokens:   "swapTokensForExactTokens(uint256,uint256,address[],address)",
	selURExecute:                     "execute(bytes,bytes[],uint256)",
	selURExecuteNoDeadline:           "execute(bytes,bytes[])",
}

// Canonical Safe MultiSend deployments (v1.3.0 and v1.4.1, MultiSend and
// MultiSendCallOnly). A Safe delegatecall to one of these, carrying a
// multiSend, is the standard batch path; a delegatecall anywhere else is
// flagged (the Bybit pattern). An address wrongly missing here can only
// over-flag, never under-flag.
var multiSendContracts = map[string]bool{
	"0xa238cbeb142c10ef7ad8442c6d1f9e89e07e7761": true, // MultiSend 1.3.0
	"0x40a2accbd92bca938b02010e17a5b8929b49130d": true, // MultiSendCallOnly 1.3.0
	"0x38869bf66a61cf6bdb996a6ae40d5853fd43b526": true, // MultiSend 1.4.1
	"0x9641d764fc13c8b624c04430c7356c1c7c8102e2": true, // MultiSendCallOnly 1.4.1
}
