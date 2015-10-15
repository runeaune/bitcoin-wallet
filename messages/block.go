package messages

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/aarbt/bitcoin-wallet/utils"
)

type GetBlocks struct {
	Version  int32
	Locators [][]byte
	HashStop []byte
}

func (g *GetBlocks) Serialize(w io.Writer) error {
	err := binary.Write(w, binary.LittleEndian, g.Version)
	if err != nil {
		return fmt.Errorf("Failed to write version field: %v", err)
	}
	err = WriteCompactUint(uint(len(g.Locators)), w)
	if err != nil {
		return fmt.Errorf("Failed to write hash count field: %v", err)
	}
	for i, l := range g.Locators {
		_, err := w.Write(l)
		if err != nil {
			return fmt.Errorf("Failed to write locator %d: %v", i, err)
		}
	}
	_, err = w.Write(g.HashStop)
	if err != nil {
		return fmt.Errorf("Failed to write hash stop field: %v", err)
	}
	return nil
}

type BlockHeader struct {
	Version    int32  // 4 bytes
	PrevBlock  []byte // 32 bytes
	MerkleRoot []byte // 32 bytes
	Timestamp  uint32
	Bits       uint32
	Nonce      uint32

	hash []byte // not in protocol message.
}

func (h *BlockHeader) Serialize(w io.Writer) error {
	err := binary.Write(w, binary.LittleEndian, h.Version)
	if err != nil {
		return fmt.Errorf("Failed to write version field: %v", err)
	}
	_, err = w.Write(h.PrevBlock)
	if err != nil {
		return fmt.Errorf("Failed to write prev block: %v", err)
	}
	_, err = w.Write(h.MerkleRoot)
	if err != nil {
		return fmt.Errorf("Failed to write merkle root: %v", err)
	}
	err = binary.Write(w, binary.LittleEndian, h.Timestamp)
	if err != nil {
		return fmt.Errorf("Failed to write timestamp: %v", err)
	}
	err = binary.Write(w, binary.LittleEndian, h.Bits)
	if err != nil {
		return fmt.Errorf("Failed to write bits: %v", err)
	}
	err = binary.Write(w, binary.LittleEndian, h.Nonce)
	if err != nil {
		return fmt.Errorf("Failed to write nonce: %v", err)
	}
	return nil
}

func (h *BlockHeader) Hash() []byte {
	if h.hash == nil {
		var b bytes.Buffer
		h.Serialize(&b)
		h.hash = utils.DoubleHash(b.Bytes())
	}
	return h.hash
}

type ExtendedHeader struct {
	BlockHeader
	Count        uint
	data         []byte    // not in protocol message.
	Height       uint      // not in protocol message.
	FetchedBlock time.Time // not in protocol message.
}

func (h *ExtendedHeader) Data() []byte {
	// TODO Serialize header if data is empty.
	return h.data
}

func (h *ExtendedHeader) Hash() []byte {
	return h.BlockHeader.Hash()
}

type Headers []*ExtendedHeader

func ParseHeaders(data []byte) (Headers, error) {
	b := bytes.NewBuffer(data)
	count, err := ParseCompactUint(b)
	if err != nil {
		return nil, fmt.Errorf("Could not read header count field: %v", err)
	}
	vector := make([]*ExtendedHeader, count)
	for i, _ := range vector {
		h, err := ParseExtendedHeader(b)
		if err != nil {
			return nil, fmt.Errorf("Could not parse tx number %d: %v", i, err)
		}
		vector[i] = h
	}
	if b.Len() != 0 {
		return nil, fmt.Errorf("Excess data: %x", b.Bytes())
	}
	return Headers(vector), nil
}

type Block struct {
	BlockHeader  // 80 bytes
	Transactions []*Transaction
	Hash         []byte // 32 bytes
}

func (b *Block) String() string {
	str := fmt.Sprintf("%x, version %d\n", utils.ReverseBytes(b.Hash), b.Version)
	str += fmt.Sprintf("PrevBlock: %x\n", b.PrevBlock)
	str += fmt.Sprintf("MerkleRoot: %x\n", b.MerkleRoot)
	str += fmt.Sprintf("Timestamp: %s (%d)\n",
		time.Unix(int64(b.Timestamp), 0), b.Timestamp)
	str += fmt.Sprintf("Bits: 0x%x\n", b.Bits)
	str += fmt.Sprintf("Transactions (%d):\n", len(b.Transactions))
	for i, tx := range b.Transactions {
		str += fmt.Sprintf("TX %d: %s\n", i, tx)
	}
	return str
}

func ParseBlock(data []byte) (*Block, error) {
	var err error
	block := Block{
		Hash: utils.DoubleHash(data[0:80]),
	}
	b := bytes.NewBuffer(data)
	block.BlockHeader, err = parseBlockHeader(b)
	if err != nil {
		return nil, err
	}
	block.Transactions, err = parseTransactions(b)
	if err != nil {
		return nil, fmt.Errorf("Could not parse transactions: %v", err)
	}
	if b.Len() != 0 {
		return nil, fmt.Errorf("Excess data: %x", b.Bytes())
	}
	return &block, nil
}

type MerkleBlock struct {
	BlockHeader // 80 bytes
	TotalTXs    uint32
	Hashes      [][]byte
	Flags       []byte
}

func ParseMerkleBlock(data []byte) (*MerkleBlock, error) {
	var err error
	block := MerkleBlock{}
	b := bytes.NewBuffer(data)
	block.BlockHeader, err = parseBlockHeader(b)
	if err != nil {
		return nil, err
	}
	err = binary.Read(b, binary.LittleEndian, &block.TotalTXs)
	if err != nil {
		return nil, fmt.Errorf("Could not parse transactions: %v", err)
	}
	block.Hashes, err = parseHashes(b)
	if err != nil {
		return nil, err
	}
	block.Flags, err = parseFlags(b)
	if err != nil {
		return nil, err
	}
	if b.Len() != 0 {
		return nil, fmt.Errorf("Excess data: %x", b.Bytes())
	}
	return &block, nil
}

func parseHashes(b io.Reader) ([][]byte, error) {
	count, err := ParseCompactUint(b)
	if err != nil {
		return nil, fmt.Errorf("Could not read hash count field: %v", err)
	}
	vector := make([][]byte, count)
	for i, _ := range vector {
		hash, err := ParseBytes(b, 32)
		if err != nil {
			return nil, fmt.Errorf("Could not parse hash %d: %v", i, err)
		}
		vector[i] = hash
	}
	return vector, nil
}

func parseFlags(b io.Reader) ([]byte, error) {
	count, err := ParseCompactUint(b)
	if err != nil {
		return nil, fmt.Errorf("Could not read flag count field: %v", err)
	}
	return ParseBytes(b, int(count))
}

func parseBlockHeader(b io.Reader) (BlockHeader, error) {
	header := BlockHeader{}
	var err error
	err = binary.Read(b, binary.LittleEndian, &header.Version)
	if err != nil {
		return header, fmt.Errorf("Could not read version field: %v", err)
	}
	header.PrevBlock, err = ParseBytes(b, 32)
	if err != nil {
		return header, fmt.Errorf("Could not read PrevBlock field: %v", err)
	}
	header.MerkleRoot, err = ParseBytes(b, 32)
	if err != nil {
		return header, fmt.Errorf("Could not read MerkleRoot field: %v", err)
	}
	err = binary.Read(b, binary.LittleEndian, &header.Timestamp)
	if err != nil {
		return header, fmt.Errorf("Could not read timestamp field: %v", err)
	}
	err = binary.Read(b, binary.LittleEndian, &header.Bits)
	if err != nil {
		return header, fmt.Errorf("Could not read bits field: %v", err)
	}
	err = binary.Read(b, binary.LittleEndian, &header.Nonce)
	if err != nil {
		return header, fmt.Errorf("Could not read bits field: %v", err)
	}
	return header, nil
}

func parseTransactions(b io.Reader) ([]*Transaction, error) {
	count, err := ParseCompactUint(b)
	if err != nil {
		return nil, fmt.Errorf("Could not read transaction count field: %v", err)
	}
	vector := make([]*Transaction, count)
	for i, _ := range vector {
		t, err := ParseTransactionFromStream(b)
		if err != nil {
			return nil, fmt.Errorf("Could not parse tx number %d: %v", i, err)
		}
		vector[i] = t
	}
	return vector, nil
}

func ParseExtendedHeader(input io.Reader) (*ExtendedHeader, error) {
	var err error
	var data bytes.Buffer
	b := io.TeeReader(input, &data)

	header := ExtendedHeader{}
	header.BlockHeader, err = parseBlockHeader(b)
	if err != nil {
		return nil, err
	}
	header.Count, err = ParseCompactUint(b)
	if err != nil {
		return nil, err
	}
	header.data = data.Bytes()
	return &header, nil
}
