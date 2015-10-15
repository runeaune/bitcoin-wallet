package messages

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/aarbt/murmur3"
)

const (
	BloomUpdateNone         = 0
	BloomUpdateAll          = 1
	BloomUpdateP2PubKeyOnly = 2
)

const (
	maxFilterLoadHashFuncs = 50
	maxFilterLoadFilterLen = 36000
)

type FilterLoad struct {
	Filter    []byte // Up to 36000 bytes
	FuncCount uint32
	Tweak     uint32
	Flags     uint8
}

func NewFilterLoad(size int, funcs uint32) (*FilterLoad, error) {
	if size > maxFilterLoadFilterLen || size < 0 {
		return nil, fmt.Errorf("Bad size %d.", size)
	}
	return &FilterLoad{
		Filter:    make([]byte, size),
		FuncCount: funcs,
	}, nil
}

func (f *FilterLoad) bloomFilter(n uint32, data []byte) uint32 {
	seed := (n*0xfba4c795 + f.Tweak) & 0xffffffff
	return murmur3.SeededSum32(seed, data) % uint32(len(f.Filter)*8)
}

func setBit(bytes []byte, bit uint32) {
	b := bit / 8
	bit = bit % 8
	if b >= uint32(len(bytes)) {
		return
	}
	bytes[b] = bytes[b] | byte(1<<bit)
}

func getBit(bytes []byte, bit uint32) bool {
	b := bit / 8
	bit = bit % 8
	if b >= uint32(len(bytes)) {
		return false
	}
	return bytes[b]&byte(1<<bit) != 0
}

func (f *FilterLoad) AddData(data []byte) {
	for i := uint32(0); i < f.FuncCount; i++ {
		bit := f.bloomFilter(i, data)
		setBit(f.Filter, bit)
	}
}

func (f *FilterLoad) MayContain(data []byte) bool {
	for i := uint32(0); i < f.FuncCount; i++ {
		bit := f.bloomFilter(i, data)
		if !getBit(f.Filter, bit) {
			return false
		}
	}
	return true
}

func (l *FilterLoad) Serialize(w io.Writer) error {
	err := WriteVarBytes(l.Filter, w)
	if err != nil {
		return fmt.Errorf("Failed to write filter field: %v", err)
	}
	err = binary.Write(w, binary.LittleEndian, l.FuncCount)
	if err != nil {
		return fmt.Errorf("Failed to write nHashFunc field: %v", err)
	}
	err = binary.Write(w, binary.LittleEndian, l.Tweak)
	if err != nil {
		return fmt.Errorf("Failed to write nTweak field: %v", err)
	}
	err = binary.Write(w, binary.LittleEndian, l.Flags)
	if err != nil {
		return fmt.Errorf("Failed to write nFlags field: %v", err)
	}
	return nil
}

func ParseFilterLoad(r io.Reader) (*FilterLoad, error) {
	f := FilterLoad{}
	var err error
	f.Filter, err = ParseVarBytes(r)
	if err != nil {
		return nil, err
	}
	if len(f.Filter) > maxFilterLoadFilterLen {
		return nil, fmt.Errorf("Filter is too big at %d bytes.",
			len(f.Filter))
	}
	binary.Read(r, binary.LittleEndian, &f.FuncCount)
	binary.Read(r, binary.LittleEndian, &f.Tweak)
	binary.Read(r, binary.LittleEndian, &f.Flags)
	return &f, nil
}

type FilterAdd struct {
	Data []byte // Up to 520 bytes
}

func (a *FilterAdd) Serialize(w io.Writer) error {
	err := WriteVarBytes(a.Data, w)
	if err != nil {
		return fmt.Errorf("Failed to write filter field: %v", err)
	}
	return nil
}
