package utils

import (
	"crypto/sha256"

	"golang.org/x/crypto/ripemd160"
)

func DoubleHash(data []byte) []byte {
	first := sha256.Sum256(data)
	hash := sha256.Sum256(first[:])
	return hash[:]
}

func RIPEMD160Hash(data []byte) []byte {
	first := sha256.Sum256(data)
	hasher := ripemd160.New()
	hasher.Write(first[:])
	hash := hasher.Sum(nil)
	return hash[:]
}

func ReverseBytes(b []byte) []byte {
	B := make([]byte, len(b))
	for i, by := range b {
		B[len(b)-1-i] = by
	}
	return B
}

type Hash []byte

/*
func (h Hash) String() string {
	reverse := make([]byte, len(h))
	for i, c := range h {
		reverse[len(h)-i-1] = c
	}
	return fmt.Sprintf("%x", reverse)
}
*/
