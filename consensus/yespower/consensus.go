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

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params/mutations"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/vars"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
)

// Yespower proof-of-work protocol constants.
var (
	maxUncles              = 2                // Maximum number of uncles allowed in a single block
	allowedFutureBlockTime = 15 * time.Second // Max time from current time allowed for blocks, before they're considered future blocks

	two256 = new(big.Int).Exp(big.NewInt(2), big.NewInt(256), big.NewInt(0))

	burnAddress = common.HexToAddress("0x000000000000000000000000000000000000dead")
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	errOlderBlockTime    = errors.New("timestamp older than parent")
	errTooManyUncles     = errors.New("too many uncles")
	errDuplicateUncle    = errors.New("duplicate uncle")
	errUncleIsAncestor   = errors.New("uncle is ancestor")
	errDanglingUncle     = errors.New("uncle's parent is not ancestor")
	errInvalidDifficulty = errors.New("non-positive difficulty")
	errInvalidPoW        = errors.New("invalid proof-of-work")
)

// Author implements consensus.Engine, returning the header's coinbase as the
// proof-of-work verified author of the block.
func (yespower *Yespower) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum yespower engine.
func (yespower *Yespower) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	// If we're running a full engine faking, accept any input as valid
	if yespower.fakeMode {
		return nil
	}
	// Short circuit if the header is known, or its parent not
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Sanity checks passed, do a proper verification
	return yespower.verifyHeader(chain, header, parent, false, seal, time.Now().Unix())
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
func (yespower *Yespower) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	// If we're running a full engine faking, accept any input as valid
	if yespower.fakeMode || len(headers) == 0 {
		abort, results := make(chan struct{}), make(chan error, len(headers))
		for i := 0; i < len(headers); i++ {
			results <- nil
		}
		return abort, results
	}

	// Spawn as many workers as allowed threads
	workers := runtime.GOMAXPROCS(0)
	if len(headers) < workers {
		workers = len(headers)
	}

	// Create a task channel and spawn the verifiers
	var (
		inputs  = make(chan int)
		done    = make(chan int, workers)
		errors  = make([]error, len(headers))
		abort   = make(chan struct{})
		unixNow = time.Now().Unix()
	)
	for i := 0; i < workers; i++ {
		go func() {
			for index := range inputs {
				errors[index] = yespower.verifyHeaderWorker(chain, headers, seals, index, unixNow)
				done <- index
			}
		}()
	}

	errorsOut := make(chan error, len(headers))
	go func() {
		defer close(inputs)
		var (
			in, out = 0, 0
			checked = make([]bool, len(headers))
			inputs  = inputs
		)
		for {
			select {
			case inputs <- in:
				if in++; in == len(headers) {
					// Reached end of headers. Stop sending to workers.
					inputs = nil
				}
			case index := <-done:
				for checked[index] = true; checked[out]; out++ {
					errorsOut <- errors[out]
					if out == len(headers)-1 {
						return
					}
				}
			case <-abort:
				return
			}
		}
	}()
	return abort, errorsOut
}

func (yespower *Yespower) verifyHeaderWorker(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool, index int, unixNow int64) error {
	var parent *types.Header
	if index == 0 {
		parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
	} else if headers[index-1].Hash() == headers[index].ParentHash {
		parent = headers[index-1]
	}
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	return yespower.verifyHeader(chain, headers[index], parent, false, seals[index], unixNow)
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of the stock Ethereum yespower engine.
func (yespower *Yespower) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	// If we're running a full engine faking, accept any input as valid
	if yespower.fakeMode {
		return nil
	}
	// Verify that there are at most 2 uncles included in this block
	if len(block.Uncles()) > maxUncles {
		return errTooManyUncles
	}
	if len(block.Uncles()) == 0 {
		return nil
	}
	// Gather the set of past uncles and ancestors
	uncles, ancestors := mapset.NewSet[common.Hash](), make(map[common.Hash]*types.Header)

	number, parent := block.NumberU64()-1, block.ParentHash()
	for i := 0; i < 7; i++ {
		ancestorHeader := chain.GetHeader(parent, number)
		if ancestorHeader == nil {
			break
		}
		ancestors[parent] = ancestorHeader
		// If the ancestor doesn't have any uncles, we don't have to iterate them
		if ancestorHeader.UncleHash != types.EmptyUncleHash {
			// Need to add those uncles to the banned list too
			ancestor := chain.GetBlock(parent, number)
			if ancestor == nil {
				break
			}
			for _, uncle := range ancestor.Uncles() {
				uncles.Add(uncle.Hash())
			}
		}
		parent, number = ancestorHeader.ParentHash, number-1
	}
	ancestors[block.Hash()] = block.Header()
	uncles.Add(block.Hash())

	// Verify each of the uncles that it's recent, but not an ancestor
	for _, uncle := range block.Uncles() {
		// Make sure every uncle is rewarded only once
		hash := uncle.Hash()
		if uncles.Contains(hash) {
			return errDuplicateUncle
		}
		uncles.Add(hash)

		// Make sure the uncle has a valid ancestry
		if ancestors[hash] != nil {
			return errUncleIsAncestor
		}
		if ancestors[uncle.ParentHash] == nil || uncle.ParentHash == block.ParentHash() {
			return errDanglingUncle
		}
		if err := yespower.verifyHeader(chain, uncle, ancestors[uncle.ParentHash], true, true, time.Now().Unix()); err != nil {
			return err
		}
	}
	return nil
}

// verifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum yespower engine.
// See YP section 4.3.4. "Block Header Validity"
func (yespower *Yespower) verifyHeader(chain consensus.ChainHeaderReader, header, parent *types.Header, uncle bool, seal bool, unixNow int64) error {
	// Ensure that the header's extra-data section is of a reasonable size (32)
	if uint64(len(header.Extra)) > vars.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), vars.MaximumExtraDataSize)
	}
	// Verify the header's timestamp
	if !uncle {
		if header.Time > uint64(unixNow+int64(allowedFutureBlockTime.Seconds())) {
			return consensus.ErrFutureBlock
		}
	}
	// Verify the timestamp
	if header.Time <= parent.Time {
		return errOlderBlockTime
	}
	// Verify the block's difficulty based on its timestamp and parent's difficulty
	expected := yespower.CalcDifficulty(chain, header.Time, parent)
	if expected.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("invalid difficulty: have %v, want %v", header.Difficulty, expected)
	}
	// Verify that the gas limit is <= 2^63-1
	if header.GasLimit > vars.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, vars.MaxGasLimit)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	// Verify that the block number is parent's +1
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}
	// Verify the block's gas usage and (if applicable) verify the base fee.
	if !chain.Config().IsEnabled(chain.Config().GetEIP1559Transition, header.Number) {
		// Verify BaseFee not present before EIP-1559 fork.
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, expected 'nil'", header.BaseFee)
		}
		if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
			return err
		}
	} else if err := eip1559.VerifyEIP1559Header(chain.Config(), parent, header); err != nil {
		// Verify the header's EIP-1559 attributes.
		return err
	}

	// Shanghai
	// EIP-4895: Beacon chain push withdrawals as operations
	// Verify the non-existence of withdrawalsHash (EIP-4895: Beacon chain push withdrawals as operations).
	eip4895Enabled := chain.Config().IsEnabledByTime(chain.Config().GetEIP4895TransitionTime, &header.Time) || chain.Config().IsEnabled(chain.Config().GetEIP4895Transition, header.Number)
	if !eip4895Enabled {
		if header.WithdrawalsHash != nil {
			return fmt.Errorf("invalid withdrawalsHash: have %x, expected nil", header.WithdrawalsHash)
		}
	} else {
		if header.WithdrawalsHash == nil {
			return errors.New("header is missing withdrawalsHash")
		}
	}

	// Cancun
	// EIP-4844: Shard Blob Txes
	// EIP-4788: Beacon block root in the EVM
	eip4844Enabled := chain.Config().IsEnabledByTime(chain.Config().GetEIP4844TransitionTime, &header.Time) || chain.Config().IsEnabled(chain.Config().GetEIP4844Transition, header.Number)
	if !eip4844Enabled {
		switch {
		case header.ExcessBlobGas != nil:
			return fmt.Errorf("invalid excessBlobGas: have %d, expected nil", header.ExcessBlobGas)
		case header.BlobGasUsed != nil:
			return fmt.Errorf("invalid blobGasUsed: have %d, expected nil", header.BlobGasUsed)
		}
	} else {
		if err := eip4844.VerifyEIP4844Header(parent, header); err != nil {
			return err
		}
	}

	// EIP-4788: Beacon block root in the EVM
	eip4788Enabled := chain.Config().IsEnabledByTime(chain.Config().GetEIP4788TransitionTime, &header.Time) || chain.Config().IsEnabled(chain.Config().GetEIP4788Transition, header.Number)
	if !eip4788Enabled {
		if header.ParentBeaconRoot != nil {
			return fmt.Errorf("invalid parentBeaconRoot, have %#x, expected nil", header.ParentBeaconRoot)
		}
	} else {
		if header.ParentBeaconRoot == nil {
			return errors.New("header is missing beaconRoot")
		}
	}

	// Verify the engine specific seal securing the block
	if seal {
		if err := yespower.verifySeal(chain, header); err != nil {
			return err
		}
	}
	return nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
func (yespower *Yespower) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return CalcDifficulty(chain.Config(), time, parent)
}

// Some weird constants to avoid constant memory allocs for them.
var (
	big1       = big.NewInt(1)
	big2       = big.NewInt(2)
	bigMinus99 = big.NewInt(-99)

	MinimumDifficulty = big.NewInt(2500) // The minimum that the difficulty may ever be.
)

// parent_time_delta is a convenience fn for CalcDifficulty
func parent_time_delta(t uint64, p *types.Header) *big.Int {
	return new(big.Int).Sub(new(big.Int).SetUint64(t), new(big.Int).SetUint64(p.Time))
}

// parent_diff_over_dbd is a  convenience fn for CalcDifficulty
func parent_diff_over_dbd(p *types.Header) *big.Int {
	return new(big.Int).Div(p.Difficulty, vars.DifficultyBoundDivisor)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
func CalcDifficulty(config ctypes.ChainConfigurator, time uint64, parent *types.Header) *big.Int {
	out := new(big.Int)

	// https://github.com/ethereum/EIPs/issues/100
	// algorithm:
	// diff = (parent_diff +
	//         (parent_diff / 2048 * max((2 if len(parent.uncles) else 1) - ((timestamp - parent.timestamp) // 9), -99))
	//        ) + 2^(periodCount - 2)
	out.Div(parent_time_delta(time, parent), vars.EIP100FDifficultyIncrementDivisor)

	if parent.UncleHash == types.EmptyUncleHash {
		out.Sub(big1, out)
	} else {
		out.Sub(big2, out)
	}
	out.Set(math.BigMax(out, bigMinus99))
	out.Mul(parent_diff_over_dbd(parent), out)
	out.Add(out, parent.Difficulty)

	// after adjustment and before bomb
	out.Set(math.BigMax(out, MinimumDifficulty))

	return out
}

// verifySeal checks whether a block satisfies the PoW difficulty requirements
func (yespower *Yespower) verifySeal(chain consensus.ChainHeaderReader, header *types.Header) error {
	// If we're running a fake PoW, accept any seal as valid
	if yespower.fakeMode {
		time.Sleep(yespower.fakeDelay)
		if yespower.fakeFail == header.Number.Uint64() {
			return errInvalidPoW
		}
		return nil
	}

	// Ensure that we have a valid difficulty for the block
	if header.Difficulty.Sign() <= 0 {
		return errInvalidDifficulty
	}

	result := yespower.calcHash(yespower.SealHash(header).Bytes(), header.Nonce.Uint64())

	target := new(big.Int).Div(two256, header.Difficulty)

	if result.Cmp(target) > 0 {
		return errInvalidPoW
	}
	return nil
}

// Prepare implements consensus.Engine, initializing the difficulty field of a
// header to conform to the yespower protocol. The changes are done inline.
func (yespower *Yespower) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = yespower.CalcDifficulty(chain, header.Time, parent)
	return nil
}

func (yespower *Yespower) AccumulateContractRewards(header *types.Header, state *state.StateDB) error {
	blockNr := rpc.BlockNumberOrHashWithHash(header.ParentHash, false)

	method := "getBlockRewards"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // cancel when we are finished consuming integers

	data, err := yespower.consensusViewABI.Pack(method, header.Number, header.Coinbase)
	if err != nil {
		log.Error("Unable to pack getBlockRewards", "error", err)
		return err
	}

	msgData := (hexutil.Bytes)(data)
	toAddress := common.HexToAddress(yespower.consensusView)
	gas := (hexutil.Uint64)(uint64(3000000))
	result, err := yespower.ethAPI.Call(ctx, ethapi.TransactionArgs{
		Gas:  &gas,
		To:   &toAddress,
		Data: &msgData,
	}, &blockNr, nil, nil)
	if err != nil {
		log.Error("Unable to call getBlockRewards", "error", err)
		return err
	}

	var staked bool
	var addresses []common.Address
	var rewards []*big.Int

	if err := yespower.consensusViewABI.UnpackIntoInterface(&[]interface{}{&staked, &addresses, &rewards}, method, result); err != nil {
		log.Error("Unable to unpack getBlockRewards", "error", err)
		return err
	}

	if !staked {
		log.Error("Miner is not staked")
		return errors.New("Miner is not staked")
	}

	for i := 0; i < len(addresses); i++ {
		state.AddBalance(addresses[i], uint256.MustFromBig(rewards[i]))
	}
	// make burn address burnable :)
	state.SetBalance(burnAddress, uint256.MustFromBig(big.NewInt(0)))

	return nil
}

// Finalize implements consensus.Engine, accumulating the block and uncle rewards.
func (yespower *Yespower) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, withdrawals []*types.Withdrawal) error {
	var err error = nil
	// Can only read state from finalized block (which is parent)
	if len(yespower.consensusView) != 0 && header.Number.Cmp(yespower.consensusViewBlock) > 0 {
		err = yespower.AccumulateContractRewards(header, state)
	} else {
		// Accumulate any block and uncle rewards and commit the final state root
		mutations.AccumulateRewards(chain.Config(), state, header, uncles)
	}
	return err
}

// FinalizeAndAssemble implements consensus.Engine, accumulating the block and
// uncle rewards, setting the final state and assembling the block.
func (yespower *Yespower) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt, withdrawals []*types.Withdrawal) (*types.Block, error) {
	if len(withdrawals) > 0 {
		return nil, errors.New("yespower does not support withdrawals")
	}
	// Finalize block
	err := yespower.Finalize(chain, header, state, txs, uncles, nil)
	if err != nil {
		return nil, err
	}

	// Assign the final state root to header.
	header.Root = state.IntermediateRoot(chain.Config().IsEnabled(chain.Config().GetEIP161dTransition, header.Number))

	// Header seems complete, assemble into a block and return
	return types.NewBlock(header, txs, uncles, receipts, trie.NewStackTrie(nil)), nil
}

// SealHash returns the hash of a block prior to it being sealed.
func (yespower *Yespower) SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()

	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if header.WithdrawalsHash != nil {
		panic("withdrawal hash set on yespower")
	}
	if header.ExcessBlobGas != nil {
		panic("excess blob gas set on yespower")
	}
	if header.BlobGasUsed != nil {
		panic("blob gas used set on yespower")
	}
	if header.ParentBeaconRoot != nil {
		panic("parent beacon root set on yespower")
	}
	rlp.Encode(hasher, enc)
	hasher.Sum(hash[:0])
	return hash
}
