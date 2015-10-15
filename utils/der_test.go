package utils

import (
	"math/big"
	"math/rand"

	"testing"
)

func randomData(r *rand.Rand, bytes int) []byte {
	data := make([]byte, bytes)
	for i, _ := range data {
		data[i] = byte(r.Uint32() % 256)
	}
	return data
}

func TestDERCoding(t *testing.T) {
	random := rand.New(rand.NewSource(0))
	for i := 0; i < 100; i++ {
		r := new(big.Int).SetBytes(randomData(random, i))
		s := new(big.Int).SetBytes(randomData(random, i))
		der := DEREncode(r, s)
		R, S, err := DERDecode(der)
		if err != nil {
			t.Fatalf("Test %d: %v", i, err)
		}
		if r.Cmp(R) != 0 {
			t.Errorf("Test %d: Decoded R mismatch: got %d, expected %d.",
				i, R, r)
		}
		if s.Cmp(S) != 0 {
			t.Errorf("Test %d: Decoded S mismatch: got %d, expected %d.",
				i, S, s)
		}
	}
}
