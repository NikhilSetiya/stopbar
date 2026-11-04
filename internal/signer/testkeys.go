package signer

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// wellKnownTestAddresses are the default accounts of the public
// "test test … junk" mnemonic that Anvil and Hardhat ship with (indices
// 0–19). Their private keys are printed on every developer's screen; a wallet
// holding one is drained the moment it is funded. Only addresses are listed.
var wellKnownTestAddresses = map[string]bool{
	"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266": true, "0x70997970c51812dc3a010c7d01b50e0d17dc79c8": true,
	"0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc": true, "0x90f79bf6eb2c4f870365e785982e1f101e93b906": true,
	"0x15d34aaf54267db7d7c367839aaf71a00a2c6a65": true, "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc": true,
	"0x976ea74026e726554db657fa54763abd0c3a0aa9": true, "0x14dc79964da2c08b23698b3d3cc7ca32193d9955": true,
	"0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f": true, "0xa0ee7a142d267c1f36714e4a8f75612f20a79720": true,
	"0xbcd4042de499d14e55001ccbb24a551f3b954096": true, "0x71be63f3384f5fb98995898a86b02fb2426c5788": true,
	"0xfabb0ac9d68b0b445fb7357272ff202c5651694a": true, "0x1cbd3b2770909d4e10f157cabc84c7264073c9ec": true,
	"0xdf3e18d64bc6a983f673ab319ccae4f1a57c7097": true, "0xcd3b766ccdd6ae721141f452c550ca635964ce71": true,
	"0x2546bcd3c84621e976d8185a91a922ae77ecec30": true, "0xbda5747bfd65f08deb54cb465eb87d40e51b197e": true,
	"0xdd2fd4581271e230360230f9337d5c0430bf44c0": true, "0x8626f6940e2eb28930efb4cef49b2d1f2c9c1199": true,
}

func isWellKnownTestKey(addr common.Address) bool {
	return wellKnownTestAddresses[strings.ToLower(addr.Hex())]
}

// ErrWellKnownKey: a published test key is never acceptable outside dev mode.
var ErrWellKnownKey = fmt.Errorf("signer: refusing a well-known test key (Anvil/Hardhat default account); its private key is public")
