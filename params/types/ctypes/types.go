// Copyright 2019 The multi-geth Authors
// This file is part of the multi-geth library.
//
// The multi-geth library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The multi-geth library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the multi-geth library. If not, see <http://www.gnu.org/licenses/>.

package ctypes

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

type UnsupportedConfigErr error

var (
	ErrUnsupportedConfigNoop  UnsupportedConfigErr = errors.New("unsupported config value (noop)")
	ErrUnsupportedConfigFatal UnsupportedConfigErr = errors.New("unsupported config value (fatal)")
)

type ErrUnsupportedConfig struct {
	Err    error
	Method string
	Value  interface{}
}

func (e ErrUnsupportedConfig) Error() string {
	return fmt.Sprintf("%v, field: %s, value: %v", e.Err, e.Method, e.Value)
}

func IsFatalUnsupportedErr(err error) bool {
	if err == nil {
		return false
	}
	return err == ErrUnsupportedConfigFatal
}

func UnsupportedConfigError(err error, method string, value interface{}) ErrUnsupportedConfig {
	return ErrUnsupportedConfig{
		Err:    err,
		Method: method,
		Value:  value,
	}
}

// Uint64Uint256ValOrMapHex is an encoding type for Parity's chain config,
// used for their 'blockReward' field.
// When only an initial value, eg 0:0x42 is set, the type is a hex-encoded string.
// When multiple values are set, eg modified block rewards, the type is a map of hex-encoded strings.
type Uint64Uint256ValOrMapHex map[uint64]*uint256.Int

// UnmarshalJSON implements the json Unmarshaler interface.
func (m *Uint64Uint256ValOrMapHex) UnmarshalJSON(input []byte) error {
	mm := make(map[math.HexOrDecimal64]math.HexOrDecimalUint256)
	err := json.Unmarshal(input, &mm)
	if err == nil {
		mp := Uint64Uint256ValOrMapHex{}
		for k, v := range mm {
			u := uint64(k)
			mp[u] = v.ToInt()
		}
		*m = mp
		return nil
	}
	uq, err := strconv.Unquote(string(input))
	if err != nil {
		return err
	}
	input = []byte(uq)
	var b = new(math.HexOrDecimalUint256)
	err = b.UnmarshalText(input)
	if err != nil {
		return err
	}
	*m = Uint64Uint256ValOrMapHex{0: b.ToInt()}
	return nil
}

// MarshalJSON implements the json Marshaler interface.
func (m Uint64Uint256ValOrMapHex) MarshalJSON() (output []byte, err error) {
	mm := make(map[math.HexOrDecimal64]*math.HexOrDecimalUint256)
	for k, v := range m {
		if v == nil {
			continue // should never happen
		}
		d := math.HexOrDecimalUint256(*v)
		mm[math.HexOrDecimal64(k)] = &d
	}
	return json.Marshal(mm)
}

// Uint64Uint256MapEncodesHex is a map that encodes and decodes w/ JSON hex format.
type Uint64Uint256MapEncodesHex map[uint64]*uint256.Int

// UnmarshalJSON implements the json Unmarshaler interface.
func (bb *Uint64Uint256MapEncodesHex) UnmarshalJSON(input []byte) error {
	// HACK: Parity uses raw numbers here...
	// It would be better to use a consistent format... instead of having to do interface{}-ing
	// and switch on types.
	m := make(map[math.HexOrDecimal64]interface{})
	err := json.Unmarshal(input, &m)
	if err != nil {
		return err
	}
	b := make(map[uint64]*uint256.Int)
	for k, v := range m {
		var vv *uint256.Int
		switch v := v.(type) {
		case string:
			var b = new(math.HexOrDecimalUint256)
			err = b.UnmarshalText([]byte(v))
			if err != nil {
				return err
			}
			vv = b.ToInt()
		case int, int64:
			vv = uint256.NewInt(uint64(v.(int64)))
		case float64:
			i, err := strconv.ParseUint(fmt.Sprintf("%.0f", v), 10, 64)
			if err != nil {
				panic(err)
			}
			vv = uint256.NewInt(i)
		default:
			panic(fmt.Sprintf("unknown type: %t %v", v, v))
		}
		if vv != nil {
			b[uint64(k)] = vv
		}
	}
	*bb = b
	return nil
}

// MarshalJSON implements the json Marshaler interface.
func (b Uint64Uint256MapEncodesHex) MarshalJSON() ([]byte, error) {
	mm := make(map[math.HexOrDecimal64]*math.HexOrDecimalUint256)
	for k, v := range b {
		if v == nil {
			continue // should never happen
		}
		d := math.HexOrDecimalUint256(*v)
		mm[math.HexOrDecimal64(k)] = &d
	}
	return json.Marshal(mm)
}

func (b Uint64Uint256MapEncodesHex) SetValueTotalForHeight(n *uint64, val *uint256.Int) {
	if n == nil || val == nil {
		return
	}

	sums := make(map[uint64]*uint256.Int)
	for k := range b {
		sums[k] = new(uint256.Int).SetUint64(b.SumValues(&k))
	}
	if sums[*n] != nil {
		if sums[*n].Cmp(val) < 0 {
			sums[*n] = val
		}
	} else {
		sums[*n] = val
	}

	sumR := uint256.NewInt(0)
	sl := []uint64{}
	for k := range sums {
		sl = append(sl, k)
	}
	sort.Slice(sl, func(i, j int) bool {
		return sl[i] < sl[j]
	})
	for _, s := range sl {
		d := new(uint256.Int).Sub(sums[s], sumR)
		b[s] = d
		sumR.Add(sumR, d)
	}
}

func (b Uint64Uint256MapEncodesHex) SumValues(n *uint64) uint64 {
	var sumB = uint256.NewInt(0)
	var sl = []uint64{}

	for k := range b {
		sl = append(sl, k)
	}
	sort.Slice(sl, func(i, j int) bool {
		return sl[i] < sl[j]
	})

	for _, s := range sl {
		if s > *n {
			// break because we're sorted chronologically,
			// all following indexes will be greater than limit n.
			break
		}
		sumB.Add(sumB, b[s])
	}

	return sumB.Uint64()
}

// MapMeetsSpecification returns the block number at which a difficulty/+reward map meet specifications, eg. EIP649 and/or EIP1234, or EIP2384.
// This is a reverse lookup to extract EIP-spec'd parameters from difficulty and reward maps implementations.
func MapMeetsSpecification(difficulties Uint64Uint256MapEncodesHex, rewards Uint64Uint256MapEncodesHex, difficultySum, wantedReward *uint256.Int) *uint64 {
	var diffN *uint64
	var sl = []uint64{}

	// difficulty
	for k := range difficulties {
		sl = append(sl, k)
	}
	sort.Slice(sl, func(i, j int) bool {
		return sl[i] < sl[j]
	})

	var total = new(uint256.Int)
	for _, s := range sl {
		d := difficulties[s]
		if d == nil {
			panic(fmt.Sprintf("dnil difficulties: %v, sl: %v", difficulties, sl))
		}
		total.Add(total, d)
		if total.Cmp(difficultySum) >= 0 {
			diffN = &s //nolint:gosec,exportloopref
			break
		}
	}
	if diffN == nil {
		// difficulty bomb delay not configured,
		// then does not meet eip649/eip1234 spec
		return nil
	}

	if wantedReward == nil || rewards == nil {
		return diffN
	}

	reward, ok := rewards[*diffN]
	if !ok {
		return nil
	}
	if reward.Cmp(wantedReward) != 0 {
		return nil
	}

	return diffN
}

type ConsensusEngineT int

const (
	ConsensusEngineT_Unknown = iota
	ConsensusEngineT_Ethash
	ConsensusEngineT_Clique
	ConsensusEngineT_Lyra2
	ConsensusEngineT_Yespower
)

func (c ConsensusEngineT) String() string {
	switch c {
	case ConsensusEngineT_Ethash:
		return "ethash"
	case ConsensusEngineT_Clique:
		return "clique"
	case ConsensusEngineT_Lyra2:
		return "lyra2"
	case ConsensusEngineT_Yespower:
		return "yespower"
	default:
		return "unknown"
	}
}

func (c ConsensusEngineT) IsEthash() bool {
	return c == ConsensusEngineT_Ethash
}

func (c ConsensusEngineT) IsClique() bool {
	return c == ConsensusEngineT_Clique
}

func (c ConsensusEngineT) IsLyra2() bool {
	return c == ConsensusEngineT_Lyra2
}

func (c ConsensusEngineT) IsYespower() bool {
	return c == ConsensusEngineT_Yespower
}

func (c ConsensusEngineT) IsUnknown() bool {
	return c == ConsensusEngineT_Unknown
}

type BlockSealingT int

const (
	BlockSealing_Unknown = iota
	BlockSealing_Ethereum
)

func (b BlockSealingT) String() string {
	switch b {
	case BlockSealing_Ethereum:
		return "ethereum"
	default:
		return "unknown"
	}
}

// TrustedCheckpoint represents a set of post-processed trie roots (CHT and
// BloomTrie) associated with the appropriate section index and head hash. It is
// used to start light syncing from this checkpoint and avoid downloading the
// entire header chain while still being able to securely access old headers/logs.
type TrustedCheckpoint struct {
	SectionIndex uint64      `json:"sectionIndex"`
	SectionHead  common.Hash `json:"sectionHead"`
	CHTRoot      common.Hash `json:"chtRoot"`
	BloomRoot    common.Hash `json:"bloomRoot"`
}

// HashEqual returns an indicator comparing the itself hash with given one.
func (c *TrustedCheckpoint) HashEqual(hash common.Hash) bool {
	if c.Empty() {
		return hash == common.Hash{}
	}
	return c.Hash() == hash
}

// Hash returns the hash of checkpoint's four key fields(index, sectionHead, chtRoot and bloomTrieRoot).
func (c *TrustedCheckpoint) Hash() common.Hash {
	buf := make([]byte, 8+3*common.HashLength)
	binary.BigEndian.PutUint64(buf, c.SectionIndex)
	copy(buf[8:], c.SectionHead.Bytes())
	copy(buf[8+common.HashLength:], c.CHTRoot.Bytes())
	copy(buf[8+2*common.HashLength:], c.BloomRoot.Bytes())
	return crypto.Keccak256Hash(buf)
}

// Empty returns an indicator whether the checkpoint is regarded as empty.
func (c *TrustedCheckpoint) Empty() bool {
	return c.SectionHead == (common.Hash{}) || c.CHTRoot == (common.Hash{}) || c.BloomRoot == (common.Hash{})
}

// CheckpointOracleConfig represents a set of checkpoint contract(which acts as an oracle)
// config which used for light client checkpoint syncing.
type CheckpointOracleConfig struct {
	Address   common.Address   `json:"address"`
	Signers   []common.Address `json:"signers"`
	Threshold uint64           `json:"threshold"`
}

// EthashConfig is the consensus engine configs for proof-of-work based sealing.
type EthashConfig struct{}

// String implements the stringer interface, returning the consensus engine details.
func (c *EthashConfig) String() string {
	return "ethash"
}

// CliqueConfig is the consensus engine configs for proof-of-authority based sealing.
type CliqueConfig struct {
	Period uint64 `json:"period"` // Number of seconds between blocks to enforce
	Epoch  uint64 `json:"epoch"`  // Epoch length to reset votes and checkpoint
}

// String implements the stringer interface, returning the consensus engine details.
func (c *CliqueConfig) String() string {
	return "clique"
}

// Lyra2Config is the consensus engine configs for MINTME network.
type Lyra2Config struct{}

// String implements the stringer interface, returning the consensus engine details.
func (c *Lyra2Config) String() string {
	return "lyra2"
}

// YespowerConfig is the consensus engine configs for Yespower PoW network.
type YespowerConfig struct {
	Pers               string   `json:"pers"`                         // (optional) Yespower personalization string to differentiate PoW between chains
	N                  uint32   `json:"N"`                            // (optional) Yespower N params
	R                  uint32   `json:"r"`                            // (optional) Yespower r params
	ConsensusView      string   `json:"consensusView"`                // (optional) ConsensusView contract to fetch block rewards
	ConsensusViewBlock *big.Int `json:"consensusViewBlock,omitempty"` // (optional) ConsensusViewBlock to start using the contract
}

// String implements the stringer interface, returning the consensus engine details.
func (c *YespowerConfig) String() string {
	return "yespower"
}
