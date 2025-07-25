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

package yespower

const consensusViewABI = `
[
  {
    "inputs": [
      {
        "internalType": "uint256",
        "name": "nHeight",
        "type": "uint256"
      },
      {
        "internalType": "address",
        "name": "coinbase",
        "type": "address"
      }
    ],
    "name": "getBlockRewards",
    "outputs": [
      {
        "internalType": "bool",
        "name": "staked",
        "type": "bool"
      },
      {
        "internalType": "address[]",
        "name": "addresses",
        "type": "address[]"
      },
      {
        "internalType": "uint256[]",
        "name": "rewards",
        "type": "uint256[]"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  }
]
`
