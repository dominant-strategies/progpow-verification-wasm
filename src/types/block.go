// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package types contains data types related to Quai consensus.
package types

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dominant-strategies/progpow-verification-wasm/common"
	"github.com/dominant-strategies/progpow-verification-wasm/rlp"
	"lukechampine.com/blake3"
)

var (
	hasher   = blake3.New(32, nil)
	hasherMu sync.RWMutex
)

// A BlockNonce is a 64-bit hash which proves (combined with the
// mix-hash) that a sufficient amount of computation has been carried
// out on a block.
type BlockNonce [8]byte

// Bytes() returns the raw bytes of the block nonce
func (n BlockNonce) Bytes() []byte {
	return n[:]
}

//go:generate gencodec -type Header -field-override headerMarshaling -out gen_header_json.go

// Header represents a block header in the Quai blockchain.
type Header struct {
	parentHash    []common.Hash   `json:"parentHash"           gencodec:"required"`
	uncleHash     common.Hash     `json:"sha3Uncles"           gencodec:"required"`
	coinbase      common.Address  `json:"miner"                gencodec:"required"`
	root          common.Hash     `json:"stateRoot"            gencodec:"required"`
	txHash        common.Hash     `json:"transactionsRoot"     gencodec:"required"`
	etxHash       common.Hash     `json:"extTransactionsRoot"  gencodec:"required"`
	etxRollupHash common.Hash     `json:"extRollupRoot"        gencodec:"required"`
	manifestHash  []common.Hash   `json:"manifestHash"         gencodec:"required"`
	receiptHash   common.Hash     `json:"receiptsRoot"         gencodec:"required"`
	difficulty    *big.Int        `json:"difficulty"           gencodec:"required"`
	parentEntropy []*big.Int      `json:"parentEntropy"        gencodec:"required"`
	parentDeltaS  []*big.Int      `json:"parentDeltaS"         gencodec:"required"`
	number        []*big.Int      `json:"number"               gencodec:"required"`
	gasLimit      uint64          `json:"gasLimit"             gencodec:"required"`
	gasUsed       uint64          `json:"gasUsed"              gencodec:"required"`
	baseFee       *big.Int        `json:"baseFeePerGas"        gencodec:"required"`
	location      common.Location `json:"location"             gencodec:"required"`
	time          uint64          `json:"timestamp"            gencodec:"required"`
	extra         []byte          `json:"extraData"            gencodec:"required"`
	mixHash       common.Hash     `json:"mixHash"              gencodec:"required"`
	nonce         BlockNonce      `json:"nonce"`

	// caches
	hash      atomic.Value
	sealHash  atomic.Value
	PowHash   atomic.Value
	PowDigest atomic.Value
}

// "external" header encoding. used for eth protocol, etc.
type extheader struct {
	ParentHash    []common.Hash
	UncleHash     common.Hash
	Coinbase      common.Address
	Root          common.Hash
	TxHash        common.Hash
	EtxHash       common.Hash
	EtxRollupHash common.Hash
	ManifestHash  []common.Hash
	ReceiptHash   common.Hash
	Difficulty    *big.Int
	ParentEntropy []*big.Int
	ParentDeltaS  []*big.Int
	Number        []*big.Int
	GasLimit      uint64
	GasUsed       uint64
	BaseFee       *big.Int
	Location      common.Location
	Time          uint64
	Extra         []byte
	MixHash       common.Hash
	Nonce         BlockNonce
}

// DecodeRLP decodes the Quai header format into h.
func (h *Header) DecodeRLP(s *rlp.Stream) error {
	var eh extheader
	if err := s.Decode(&eh); err != nil {
		return err
	}
	h.parentHash = eh.ParentHash
	h.uncleHash = eh.UncleHash
	h.coinbase = eh.Coinbase
	h.root = eh.Root
	h.txHash = eh.TxHash
	h.etxHash = eh.EtxHash
	h.etxRollupHash = eh.EtxRollupHash
	h.manifestHash = eh.ManifestHash
	h.receiptHash = eh.ReceiptHash
	h.difficulty = eh.Difficulty
	h.parentEntropy = eh.ParentEntropy
	h.parentDeltaS = eh.ParentDeltaS
	h.number = eh.Number
	h.gasLimit = eh.GasLimit
	h.gasUsed = eh.GasUsed
	h.baseFee = eh.BaseFee
	h.location = eh.Location
	h.time = eh.Time
	h.extra = eh.Extra
	h.mixHash = eh.MixHash
	h.nonce = eh.Nonce

	return nil
}

// EncodeRLP serializes h into the Quai RLP block format.
func (h *Header) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, extheader{
		ParentHash:    h.parentHash,
		UncleHash:     h.uncleHash,
		Coinbase:      h.coinbase,
		Root:          h.root,
		TxHash:        h.txHash,
		EtxHash:       h.etxHash,
		EtxRollupHash: h.etxRollupHash,
		ManifestHash:  h.manifestHash,
		ReceiptHash:   h.receiptHash,
		Difficulty:    h.difficulty,
		ParentEntropy: h.parentEntropy,
		ParentDeltaS:  h.parentDeltaS,
		Number:        h.number,
		GasLimit:      h.gasLimit,
		GasUsed:       h.gasUsed,
		BaseFee:       h.baseFee,
		Location:      h.location,
		Time:          h.time,
		Extra:         h.extra,
		MixHash:       h.mixHash,
		Nonce:         h.nonce,
	})
}

// Localized accessors
func (h *Header) ParentHash(args ...int) common.Hash {
	nodeCtx := common.NodeLocation.Context()
	if len(args) > 0 {
		nodeCtx = args[0]
	}
	return h.parentHash[nodeCtx]
}
func (h *Header) UncleHash() common.Hash {
	return h.uncleHash
}
func (h *Header) Coinbase() common.Address {
	return h.coinbase
}
func (h *Header) Root() common.Hash {
	return h.root
}
func (h *Header) TxHash() common.Hash {
	return h.txHash
}
func (h *Header) EtxHash() common.Hash {
	return h.etxHash
}
func (h *Header) EtxRollupHash() common.Hash {
	return h.etxRollupHash
}
func (h *Header) ParentEntropy(args ...int) *big.Int {
	nodeCtx := common.NodeLocation.Context()
	if len(args) > 0 {
		nodeCtx = args[0]
	}
	return h.parentEntropy[nodeCtx]
}
func (h *Header) ParentDeltaS(args ...int) *big.Int {
	nodeCtx := common.NodeLocation.Context()
	if len(args) > 0 {
		nodeCtx = args[0]
	}
	return h.parentDeltaS[nodeCtx]
}
func (h *Header) ManifestHash(args ...int) common.Hash {
	nodeCtx := common.NodeLocation.Context()
	if len(args) > 0 {
		nodeCtx = args[0]
	}
	return h.manifestHash[nodeCtx]
}
func (h *Header) ReceiptHash() common.Hash {
	return h.receiptHash
}
func (h *Header) Difficulty() *big.Int {
	return h.difficulty
}
func (h *Header) Number(args ...int) *big.Int {
	nodeCtx := common.NodeLocation.Context()
	if len(args) > 0 {
		nodeCtx = args[0]
	}
	return h.number[nodeCtx]
}
func (h *Header) NumberU64(args ...int) uint64 {
	nodeCtx := common.NodeLocation.Context()
	if len(args) > 0 {
		nodeCtx = args[0]
	}
	return h.number[nodeCtx].Uint64()
}
func (h *Header) GasLimit() uint64 {
	return h.gasLimit
}
func (h *Header) GasUsed() uint64 {
	return h.gasUsed
}
func (h *Header) BaseFee() *big.Int {
	return h.baseFee
}
func (h *Header) Location() common.Location { return h.location }
func (h *Header) Time() uint64              { return h.time }
func (h *Header) Extra() []byte             { return common.CopyBytes(h.extra) }
func (h *Header) MixHash() common.Hash      { return h.mixHash }
func (h *Header) Nonce() BlockNonce         { return h.nonce }
func (h *Header) NonceU64() uint64          { return binary.BigEndian.Uint64(h.nonce[:]) }

// headerData comprises all data fields of the header, excluding the nonce, so
// that the nonce may be independently adjusted in the work algorithm.
type sealData struct {
	ParentHash    []common.Hash
	UncleHash     common.Hash
	Coinbase      common.Address
	Root          common.Hash
	TxHash        common.Hash
	EtxHash       common.Hash
	EtxRollupHash common.Hash
	ManifestHash  []common.Hash
	ReceiptHash   common.Hash
	Number        []*big.Int
	GasLimit      uint64
	GasUsed       uint64
	BaseFee       *big.Int
	Difficulty    *big.Int
	Location      common.Location
	Time          uint64
	Extra         []byte
	Nonce         BlockNonce
}

// SealHash returns the hash of a block prior to it being sealed.
func (h *Header) SealHash() (hash common.Hash) {
	hasherMu.Lock()
	defer hasherMu.Unlock()
	hasher.Reset()
	hdata := sealData{
		ParentHash:    make([]common.Hash, common.HierarchyDepth),
		UncleHash:     h.UncleHash(),
		Coinbase:      h.Coinbase(),
		Root:          h.Root(),
		TxHash:        h.TxHash(),
		EtxHash:       h.EtxHash(),
		EtxRollupHash: h.EtxRollupHash(),
		ManifestHash:  make([]common.Hash, common.HierarchyDepth),
		ReceiptHash:   h.ReceiptHash(),
		Number:        make([]*big.Int, common.HierarchyDepth),
		GasLimit:      h.GasLimit(),
		GasUsed:       h.GasUsed(),
		BaseFee:       h.BaseFee(),
		Difficulty:    h.Difficulty(),
		Location:      h.Location(),
		Time:          h.Time(),
		Extra:         h.Extra(),
	}
	for i := 0; i < common.HierarchyDepth; i++ {
		hdata.ParentHash[i] = h.ParentHash(i)
		hdata.ManifestHash[i] = h.ManifestHash(i)
		hdata.Number[i] = h.Number(i)
	}
	rlp.Encode(hasher, hdata)
	hash.SetBytes(hasher.Sum(hash[:0]))
	return hash
}

// Hash returns the nonce'd hash of the header. This is just the Blake3 hash of
// SealHash suffixed with a nonce.
func (h *Header) Hash() (hash common.Hash) {
	sealHash := h.SealHash().Bytes()
	hasherMu.Lock()
	defer hasherMu.Unlock()
	hasher.Reset()
	var hData [40]byte
	copy(hData[:], h.Nonce().Bytes())
	copy(hData[len(h.nonce):], sealHash)
	sum := blake3.Sum256(hData[:])
	hash.SetBytes(sum[:])
	return hash
}

// totalBitLen returns the cumulative BitLen for each element in a big.Int slice.
func totalBitLen(array []*big.Int) int {
	bitLen := 0
	for _, item := range array {
		if item != nil {
			bitLen += item.BitLen()
		}
	}
	return bitLen
}

var headerSize = common.StorageSize(reflect.TypeOf(Header{}).Size())

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (h *Header) Size() common.StorageSize {
	return headerSize + common.StorageSize(len(h.extra)+(h.difficulty.BitLen()+totalBitLen(h.number))/8)
}

// Block represents an entire block in the Quai blockchain.
type Block struct {
	header          *Header
	uncles          []*Header
	transactions    Transactions
	extTransactions Transactions
	subManifest     BlockManifest

	// caches
	size       atomic.Value
	appendTime atomic.Value

	// These fields are used by package eth to track
	// inter-peer block relay.
	ReceivedAt   time.Time
	ReceivedFrom interface{}
}

// "external" block encoding. used for eth protocol, etc.
type extblock struct {
	Header      *Header
	Txs         []*Transaction
	Uncles      []*Header
	Etxs        []*Transaction
	SubManifest BlockManifest
}

// DecodeRLP decodes the Quai RLP encoding into b.
func (b *Block) DecodeRLP(s *rlp.Stream) error {
	var eb extblock
	_, size, _ := s.Kind()
	if err := s.Decode(&eb); err != nil {
		return err
	}
	b.header, b.uncles, b.transactions, b.extTransactions, b.subManifest = eb.Header, eb.Uncles, eb.Txs, eb.Etxs, eb.SubManifest
	b.size.Store(common.StorageSize(rlp.ListSize(size)))
	return nil
}

// EncodeRLP serializes b into the Quai RLP block format.
func (b *Block) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, extblock{
		Header:      b.header,
		Txs:         b.transactions,
		Uncles:      b.uncles,
		Etxs:        b.extTransactions,
		SubManifest: b.subManifest,
	})
}

// Wrapped header accessors
func (b *Block) ParentHash(args ...int) common.Hash   { return b.header.ParentHash(args...) }
func (b *Block) UncleHash() common.Hash               { return b.header.UncleHash() }
func (b *Block) Coinbase() common.Address             { return b.header.Coinbase() }
func (b *Block) Root() common.Hash                    { return b.header.Root() }
func (b *Block) TxHash() common.Hash                  { return b.header.TxHash() }
func (b *Block) EtxHash() common.Hash                 { return b.header.EtxHash() }
func (b *Block) EtxRollupHash() common.Hash           { return b.header.EtxRollupHash() }
func (b *Block) ManifestHash(args ...int) common.Hash { return b.header.ManifestHash(args...) }
func (b *Block) ReceiptHash() common.Hash             { return b.header.ReceiptHash() }
func (b *Block) Difficulty(args ...int) *big.Int      { return b.header.Difficulty() }
func (b *Block) ParentEntropy(args ...int) *big.Int   { return b.header.ParentEntropy(args...) }
func (b *Block) ParentDeltaS(args ...int) *big.Int    { return b.header.ParentDeltaS(args...) }
func (b *Block) Number(args ...int) *big.Int          { return b.header.Number(args...) }
func (b *Block) NumberU64(args ...int) uint64         { return b.header.NumberU64(args...) }
func (b *Block) GasLimit() uint64                     { return b.header.GasLimit() }
func (b *Block) GasUsed() uint64                      { return b.header.GasUsed() }
func (b *Block) BaseFee() *big.Int                    { return b.header.BaseFee() }
func (b *Block) Location() common.Location            { return b.header.Location() }
func (b *Block) Time() uint64                         { return b.header.Time() }
func (b *Block) Extra() []byte                        { return b.header.Extra() }
func (b *Block) Nonce() BlockNonce                    { return b.header.Nonce() }
func (b *Block) NonceU64() uint64                     { return b.header.NonceU64() }

// PendingHeader stores the header and termini value associated with the header.
type PendingHeader struct {
	header  *Header `json:"header"`
	termini Termini `json:"termini"`
}

// "external" pending header encoding. used for rlp
type extPendingHeader struct {
	Header  *Header
	Termini Termini
}

// DecodeRLP decodes the Quai RLP encoding into pending header format.
func (p *PendingHeader) DecodeRLP(s *rlp.Stream) error {
	var eb extPendingHeader
	if err := s.Decode(&eb); err != nil {
		return err
	}
	p.header, p.termini = eb.Header, eb.Termini
	return nil
}

// EncodeRLP serializes b into the Quai RLP format.
func (p PendingHeader) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, extPendingHeader{
		Header:  p.header,
		Termini: p.termini,
	})
}

// Termini stores the dom terminus (i.e the previous dom block) and
// subTermini(i.e the dom blocks that have occured in the subordinate chains)
type Termini struct {
	domTermini []common.Hash `json:"domTermini"`
	subTermini []common.Hash `json:"subTermini"`
}

// "external termini" pending header encoding. used for rlp
type extTermini struct {
	DomTermini []common.Hash
	SubTermini []common.Hash
}

// DecodeRLP decodes the Quai RLP encoding into pending header format.
func (t *Termini) DecodeRLP(s *rlp.Stream) error {
	var et extTermini
	if err := s.Decode(&et); err != nil {
		return err
	}
	t.domTermini, t.subTermini = et.DomTermini, et.SubTermini
	return nil
}

// EncodeRLP serializes b into the Quai RLP format.
func (t Termini) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, extTermini{
		DomTermini: t.domTermini,
		SubTermini: t.subTermini,
	})
}

// BlockManifest is a list of block hashes, which implements DerivableList
type BlockManifest []common.Hash

// Len returns the length of s.
func (m BlockManifest) Len() int { return len(m) }

// EncodeIndex encodes the i'th blockhash to w.
func (m BlockManifest) EncodeIndex(i int, w *bytes.Buffer) {
	rlp.Encode(w, m[i])
}
