package utils

import (
	"fmt"
	"math/big"

	"github.com/aarbt/bitcoin-crypto/bitelliptic"
)

//These functions are from hdkeys
// TODO Figure out how to share them

// ParseUncompressed parses a 65 bytes uncompressed public address into a (X,Y)
// point on the curve.
func ParseUncompressed(d []byte) (*big.Int, *big.Int, error) {
	if len(d) != 65 {
		return nil, nil, fmt.Errorf("Input has wrong length %d (expected 65).", len(d))
	}
	if d[0] != 0x04 {
		return nil, nil, fmt.Errorf("Input has wrong prefix 0x%x (expected 0x04).", d[0])
	}
	return new(big.Int).SetBytes(d[1:33]), new(big.Int).SetBytes(d[33:65]), nil
}

func ParseCompact(b []byte) (*big.Int, *big.Int, error) {
	if len(b) != 33 {
		return nil, nil, fmt.Errorf("Data \"%x\" isn't 33 bytes.", b)
	}
	curve := bitelliptic.S256()

	// y = sqrt(x^3 + B) mod P
	x := new(big.Int).SetBytes(b[1:33])
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	y2 := new(big.Int).Add(x3, curve.B)
	y2.Mod(y2, curve.P)

	// sqrt(a) = a^((P+1)/4)
	e := big.NewInt(1)
	e = e.Add(e, curve.P)
	e = e.Div(e, big.NewInt(4))
	y := y2.Exp(y2, e, curve.P)

	switch b[0] {
	case 0x02:
		// y should be even.
		if y.Bit(0) == 1 {
			y = y.Sub(curve.P, y)
		}
	case 0x03:
		// y should be odd.
		if y.Bit(0) == 0 {
			y = y.Sub(curve.P, y)
		}
	default:
		// TODO consider panicking if functions is private.
		return nil, nil, fmt.Errorf("Bad prefix 0x%x.", b[0])
	}
	return x, y, nil
}

func ParsePublicKey(d []byte) (*big.Int, *big.Int, error) {
	if len(d) == 65 && d[0] == 0x04 {
		return ParseUncompressed(d)
	} else if len(d) == 33 && (d[0] == 0x02 || d[0] == 0x03) {
		return ParseCompact(d)
	} else {
		return nil, nil, fmt.Errorf("Unknown format.")
	}
}

// SerializeUncompressed serializes a point on the curve into a 65 byte
// long byte array.
func SerializeUncompressed(x, y *big.Int) []byte {
	X := x.Bytes()
	Y := y.Bytes()

	// Pad leading zeros for short integers.
	paddingX := 32 - len(X)
	paddingY := 32 - len(Y)

	b := make([]byte, 65)
	b[0] = 0x04
	copy(b[1+paddingX:33], X)
	copy(b[33+paddingY:65], Y)
	return b
}
