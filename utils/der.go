package utils

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
)

func writeDERInt(w io.Writer, i *big.Int) int {
	I := i.Bytes()
	lenI := len(I)

	if len(I) > 0 && I[0] > 0x7f {
		lenI++
	}
	w.Write([]byte{0x02, byte(lenI)})
	if len(I) > 0 && I[0] > 0x7f {
		w.Write([]byte{0x00})
	}
	w.Write(I)
	return lenI + 2
}

func DEREncode(r, s *big.Int) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x30, 0xFF}) // 0xFF is placeholder for total length.
	l := writeDERInt(&b, r)
	l += writeDERInt(&b, s)
	res := b.Bytes()
	res[1] = byte(l) // Write total length.
	return res
}

func DERDecode(b []byte) (*big.Int, *big.Int, error) {
	if len(b) < 6 || b[0] != 0x30 || int(b[1]) != len(b)-2 {
		return nil, nil, fmt.Errorf("Input has bad format.")
	}
	lenR := int(b[3])
	r := new(big.Int).SetBytes(b[4 : 4+lenR])
	lenS := int(b[5+lenR])
	s := new(big.Int).SetBytes(b[6+lenR : 6+lenR+lenS])
	return r, s, nil
}
