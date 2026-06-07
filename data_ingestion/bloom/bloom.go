package bloom

import "sync"

func fnv1a(data []byte) uint64 {
	const (
		offset uint64 = 14695981039346656037
		prime  uint64 = 1099511628211
	)

	h := offset
	for _, b := range data {
		h ^= uint64(b)
		h *= prime
	}
	return h
}

func fnv1aSeed(data []byte, seed uint64) uint64 {
	const prime uint64 = 1099511628211
	h := seed
	for _, b := range data {
		h ^= uint64(b)
		h *= prime
	}

	return h
}

type BloomFilter struct {
	bits []uint64
	m    uint //total no. of bits
	k    uint //no. of hash functions
	mu   sync.Mutex
}

func New(m, k uint) *BloomFilter {
	words := (m + 63) / 64 //array contains multiple 64 bit data, word determines the no. of 64 bit data required in the array,  ex. we have total m=65 bits then array will have 65+63/64 = 2 i.e 2 words required in the array to hold all bits

	return &BloomFilter{
		bits: make([]uint64, words),
		m:    m,
		k:    k,
	}
}

func (bf *BloomFilter) setBit(pos uint) {
	bf.bits[pos/64] |= (uint64(1) << (pos % 64)) // we use OR operations to set bit, we need to first shift the original data and then applying OR to flip the bit
}

func (bf *BloomFilter) getBit(pos uint) bool {
	return bf.bits[pos/64]&(uint64(1)<<(pos%64)) != 0 // we use AND operations to get bit, we need to first use mask on the original data and then using AND and then then checking if it is 0
}

func (bf *BloomFilter) TestAndAdd(data []byte) (alreadyPresent bool) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	// kirtz-mitzenmacher optimization
	h := fnv1a(data)
	low := uint64(uint32(h))
	high := uint64(h >> 32)

	alreadyPresent = true

	for i := uint(0); i < bf.k; i++ {
		pos := uint((low + uint64(i)*high) % uint64(bf.m))
		if !bf.getBit(pos) {
			alreadyPresent = false
		}
	}
	for i := uint(0); i < bf.k; i++ {
		pos := uint((low + uint64(i)*high) % uint64(bf.m))
		bf.setBit(pos)
	}

	return alreadyPresent

}
