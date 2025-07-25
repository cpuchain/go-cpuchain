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

/*
#cgo CFLAGS: -std=gnu99
#include "yespower.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/binary"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/rpc"
)

type Yespower struct {
	ethAPI             *ethapi.BlockChainAPI
	pers               string
	consensusView      string
	consensusViewBlock *big.Int
	consensusViewABI   abi.ABI

	fakeMode  bool
	fakeFail  uint64
	fakeDelay time.Duration

	log  log.Logger
	lock sync.Mutex

	rand     *rand.Rand
	hashrate metrics.Meter
	update   chan struct{}
	threads  int
	remote   *remoteSealer
}

type Config struct {
	FakeMode  bool
	FakeFail  uint64
	FakeDelay time.Duration

	Log  log.Logger
	Rand *rand.Rand
}

func New(config *Config, yesConfig *ctypes.YespowerConfig, ethAPI *ethapi.BlockChainAPI, notify []string, noverify bool) *Yespower {
	// This is required in order for hashrate meter to work
	if !metrics.Enabled {
		metrics.Enabled = true
	}
	if config == nil {
		config = &Config{}
	}
	cABI, err := abi.JSON(strings.NewReader(consensusViewABI))
	if err != nil {
		panic(err)
	}
	yespower := &Yespower{
		ethAPI:             ethAPI,
		pers:               yesConfig.Pers,
		consensusView:      yesConfig.ConsensusView,
		consensusViewBlock: yesConfig.ConsensusViewBlock,
		consensusViewABI:   cABI,
		fakeMode:           config.FakeMode,
		fakeFail:           config.FakeFail,
		fakeDelay:          config.FakeDelay,
		log:                log.Root(),
		hashrate:           metrics.NewMeter(),
		update:             make(chan struct{}),
	}
	if config.Log != nil {
		yespower.log = config.Log
	}
	if config.Rand != nil {
		yespower.rand = config.Rand
	}
	yespower.remote = startRemoteSealer(yespower, notify, noverify)
	return yespower
}

func NewTester(notify []string, noverify bool) *Yespower {
	yespower := &Yespower{
		pers:      "",
		fakeMode:  false,
		fakeFail:  0,
		fakeDelay: 0,
		log:       log.Root(),
		hashrate:  metrics.NewMeter(),
		update:    make(chan struct{}),
	}
	yespower.remote = startRemoteSealer(yespower, notify, noverify)
	return yespower
}

// Copied from hashimoto function from ethash
func (yespower *Yespower) calcHash(hash []byte, nonce uint64) *big.Int {
	// Combine header+nonce into a 40 byte seed (while hash is 32 bytes and nonce 8 bytes)
	seed := make([]byte, 40)
	copy(seed, hash)
	binary.LittleEndian.PutUint64(seed[32:], nonce)

	result := compute(seed, yespower.pers)
	return new(big.Int).SetBytes(result)
}

func compute(input []byte, per string) []byte {
	var in unsafe.Pointer = C.CBytes(input)
	var cPer unsafe.Pointer = unsafe.Pointer(C.CString(per))
	var out unsafe.Pointer = C.malloc(32)

	C.yespower_hash((*C.char)(in), C.uint(len(input)), (*C.char)(cPer), C.uint(len(per)), (*C.char)(out))

	hashed := C.GoBytes(out, 32)

	C.free(in)
	C.free(cPer)
	C.free(out)

	return hashed
}

func (yespower *Yespower) Close() error {
	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC APIs.
func (yespower *Yespower) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   &API{yespower},
			Public:    true,
		},
	}
}

func (yespower *Yespower) Hashrate() float64 {
	return yespower.hashrate.Snapshot().Rate1()
}

// Threads returns the number of mining threads currently enabled. This doesn't
// necessarily mean that mining is running!
func (yespower *Yespower) Threads() int {
	yespower.lock.Lock()
	defer yespower.lock.Unlock()

	return yespower.threads
}

// SetThreads updates the number of mining threads currently enabled. Calling
// this method does not start mining, only sets the thread count. If zero is
// specified, the miner will use all cores of the machine. Setting a thread
// count below zero is allowed and will cause the miner to idle, without any
// work being done.
func (yespower *Yespower) SetThreads(threads int) {
	yespower.lock.Lock()
	defer yespower.lock.Unlock()

	// Update the threads and ping any running seal to pull in any changes
	yespower.threads = threads
	select {
	case yespower.update <- struct{}{}:
	default:
	}
}
