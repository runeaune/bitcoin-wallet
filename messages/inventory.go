package messages

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	TypeError            = 0
	TypeMsgTX            = 1
	TypeMsgBlock         = 2
	TypeMsgFilteredBlock = 3
)

func TypeString(t uint32) string {
	switch t {
	case TypeError:
		return "Error"
	case TypeMsgTX:
		return "TX"
	case TypeMsgBlock:
		return "Block"
	case TypeMsgFilteredBlock:
		return "Filtered block"
	default:
		return "<unknown type>"
	}
}

type Inventory struct {
	Type uint32
	Hash []byte
}

func (i *Inventory) Write(w io.Writer) error {
	err := binary.Write(w, binary.LittleEndian, i.Type)
	if err != nil {
		return fmt.Errorf("Failed to write type field: %v", err)
	}
	n, err := w.Write(i.Hash)
	if err != nil || n != len(i.Hash) {
		return fmt.Errorf("Failed to write hash field: %d, %v", n, err)
	}
	return nil
}

type InventoryVector []*Inventory

func ParseInventory(b io.Reader) (*Inventory, error) {
	i := Inventory{}
	var err error
	err = binary.Read(b, binary.LittleEndian, &i.Type)
	if err != nil {
		return nil, fmt.Errorf("Could not read type field: %v", err)
	}
	if i.Type == TypeError || i.Type > 3 {
		return nil, fmt.Errorf("Bad inventory type %d.", i.Type)
	}
	i.Hash, err = ParseBytes(b, 32)
	if err != nil {
		return nil, fmt.Errorf("Could not read hash field: %v", err)
	}
	return &i, nil
}

func ParseInventoryVector(data []byte) (InventoryVector, error) {
	b := bytes.NewBuffer(data)
	count, err := ParseCompactUint(b)
	if err != nil {
		return nil, fmt.Errorf("Could not read count field: %v", err)
	}
	vector := make([]*Inventory, count)
	for i := uint(0); i < count; i++ {
		inv, err := ParseInventory(b)
		if err != nil {
			return nil, fmt.Errorf("Could not parse inventory field number %d: %v",
				i, err)
		}
		vector[i] = inv
	}
	return vector, nil
}

func EncodeInventoryVector(inv InventoryVector) ([]byte, error) {
	buf := new(bytes.Buffer)
	err := WriteCompactUint(uint(len(inv)), buf)
	if err != nil {
		return nil, fmt.Errorf("Failed to write compact uint: %v", err)
	}
	for count, i := range inv {
		err := i.Write(buf)
		if err != nil {
			return nil, fmt.Errorf("Failed to write inv #%d: %v", count, err)
		}
	}
	return buf.Bytes(), nil
}

/*
func (v *InventoryVector) AppendInventory(t uint32, hash []byte) error {
	if t == TypeError || t > 3 {
		return fmt.Errorf("Bad inventory type %d.", t)
	}
	if len(hash) != 32 {
		return fmt.Errorf("Bad inventory hash length %d.", len(hash))
	}
	v = append(v, &Inventory{
		Type: t,
		Hash: hash,
	})
	return nil
}
*/
