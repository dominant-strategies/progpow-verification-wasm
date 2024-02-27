// Copyright 2015 The go-ethereum Authors
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

package common

import (
	"errors"
	"log"
	"strconv"

	"github.com/dominant-strategies/progpow-verification-wasm/common/hexutil"
)

// Lengths of hashes and addresses in bytes.
const (
	// HashLength is the expected length of the hash
	HashLength = 32
	// AddressLength is the expected length of the address
	AddressLength = 20

	// Constants to mnemonically index into context arrays
	PRIME_CTX  = 0
	REGION_CTX = 1
	ZONE_CTX   = 2

	// Depth of the hierarchy of chains
	NumRegionsInPrime = 3
	NumZonesInRegion  = 3
	HierarchyDepth    = 3
	NumChains         = 1 + NumRegionsInPrime*(1+NumZonesInRegion) // Prime + R regions + RxZ zones
)

var (
	// Default to prime node, but changed at startup by config.
	NodeLocation = Location{}
)

var (
	// The zero address (0x0)
	ZeroInternal    = InternalAddress{}
	ZeroAddr        = Address{&ZeroInternal}
	ErrInvalidScope = errors.New("address is not in scope")
)

// Hash represents the 32 byte Keccak256 hash of arbitrary data.
type Hash [HashLength]byte

// BytesToHash sets b to hash.
// If b is larger than len(h), b will be cropped from the left.
func BytesToHash(b []byte) Hash {
	var h Hash
	h.SetBytes(b)
	return h
}

// Bytes gets the byte representation of the underlying hash.
func (h Hash) Bytes() []byte { return h[:] }

// Hex converts a hash to a hex string.
func (h Hash) Hex() string { return hexutil.Encode(h[:]) }

// SetBytes sets the hash to the value of b.
// If b is larger than len(h), b will be cropped from the left.
func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-HashLength:]
	}

	copy(h[HashLength-len(b):], b)
}

/////////// Address

type addrPrefixRange struct {
	lo uint8
	hi uint8
}

var locationToPrefixRange = make(map[string]addrPrefixRange)

// Location of a chain within the Quai hierarchy
// Location is encoded as a path from the root of the tree to the specified
// chain. Not all indices need to be populated, e.g:
// prime     = []
// region[0] = [0]
// zone[1,2] = [1, 2]
type Location []byte

func (loc Location) Region() int {
	if len(loc) >= 1 {
		return int(loc[REGION_CTX-1])
	} else {
		return -1
	}
}

func (loc Location) HasRegion() bool {
	return loc.Region() >= 0
}

func (loc Location) Zone() int {
	if len(loc) >= 2 {
		return int(loc[ZONE_CTX-1])
	} else {
		return -1
	}
}

func (loc Location) HasZone() bool {
	return loc.Zone() >= 0
}

func (loc Location) AssertValid() {
	if !loc.HasRegion() && loc.HasZone() {
		log.Fatal("cannot specify zone without also specifying region.")
	}
	if loc.Region() >= NumRegionsInPrime {
		log.Fatal("region index is not valid.")
	}
	if loc.Zone() >= NumZonesInRegion {
		log.Fatal("zone index is not valid.")
	}
}

func (loc Location) Context() int {
	loc.AssertValid()
	if loc.Zone() >= 0 {
		return ZONE_CTX
	} else if loc.Region() >= 0 {
		return REGION_CTX
	} else {
		return PRIME_CTX
	}
}

func (loc Location) Name() string {
	regionName := ""
	switch loc.Region() {
	case 0:
		regionName = "cyprus"
	case 1:
		regionName = "paxos"
	case 2:
		regionName = "hydra"
	default:
		regionName = "unknownregion"
	}
	zoneNum := strconv.Itoa(loc.Zone() + 1)
	switch loc.Context() {
	case PRIME_CTX:
		return "prime"
	case REGION_CTX:
		return regionName
	case ZONE_CTX:
		return regionName + zoneNum
	default:
		log.Println("cannot name invalid location")
		return "invalid-location"
	}
}

func (l Location) ContainsAddress(a Address) bool {
	// ContainAddress can only be called for a zone chain
	if l.Context() != ZONE_CTX {
		return false
	}
	prefix := a.Bytes()[0]
	prefixRange, ok := locationToPrefixRange[l.Name()]
	if !ok {
		log.Fatal("unable to get address prefix range for location")
	}
	// Ranges are fully inclusive
	return uint8(prefix) >= prefixRange.lo && uint8(prefix) <= prefixRange.hi
}

func IsInChainScope(b []byte) bool {
	nodeCtx := NodeLocation.Context()
	// IsInChainScope only be called for a zone chain
	if nodeCtx != ZONE_CTX {
		return false
	}
	if BytesToHash(b) == ZeroAddr.Hash() {
		return true
	}
	prefix := b[0]
	prefixRange, ok := locationToPrefixRange[NodeLocation.Name()]
	if !ok {
		log.Fatal("unable to get address prefix range for location")
	}
	// Ranges are fully inclusive
	return uint8(prefix) >= prefixRange.lo && uint8(prefix) <= prefixRange.hi
}
