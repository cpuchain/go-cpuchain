// Copyright 2025 The core-geth Authors
// This file is part of the core-geth library.
//
// The core-geth library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The core-geth library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the core-geth library. If not, see <http://www.gnu.org/licenses/>.

package params

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/params/types/genesisT"
)

var CPUchainGenesisHash = common.HexToHash("0xd4f9bdb12aca024701d5b35446ad768d70357a97321d1a868fa999e44ffdedec")

// CPUchainGenesisBlock returns the CPUchain genesis block.
func DefaultCPUchainGenesisBlock() *genesisT.Genesis {
	return &genesisT.Genesis{
		Config:     CPUChainConfig,
		Nonce:      hexutil.MustDecodeUint64("0x0"),
		ExtraData:  hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   30000000,
		Difficulty: big.NewInt(2500),
		Timestamp:  0,
		Alloc:      genesisT.DecodePreAlloc(allocCPUchain),
	}
}
