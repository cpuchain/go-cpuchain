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
	"testing"
)

// TestGenesisHashCPUchain tests that CPUchainGenesisHash is the correct value for the genesis configuration.
func TestGenesisHashCPUchain(t *testing.T) {
	genesis := DefaultCPUchainGenesisBlock()
	block := genesisToBlock(genesis, nil)
	if block.Hash() != CPUchainGenesisHash {
		t.Errorf("want: %s, got: %s", CPUchainGenesisHash.Hex(), block.Hash().Hex())
	}
}
