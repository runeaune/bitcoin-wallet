package inventory

import (
	"fmt"

	"github.com/aarbt/bitcoin-wallet/utils"
)

type MerkleNode struct {
	Left, Right *MerkleNode
	Hash        []byte
	match       bool
	level       int
	rank        int
}

// EmptyMerkleTree construct an empty merkle tree with count transactions in
// it. It returns the root of the tree.
func NewMerkleTree(count uint32, hashArray [][]byte, flags []byte) (*MerkleNode, error) {
	hashes := &HashStack{hashArray, 0}
	bits := &BitStack{flags, 0}
	root := &MerkleNode{}
	levels := merkleTreeLevels(count)
	// Process the tree from the root down. If the tree is correctly
	// formated, we'll run out of hashes exactly when we need to start
	// copying from the left sibling.
	err := root.Process(hashes, bits, levels)
	if err != nil {
		return nil, err
	}
	if hashes.Size() != 0 {
		return nil, fmt.Errorf("Ended processing with %d left over hashes.",
			hashes.Size())
	}
	if bits.Size() > 7 {
		return nil, fmt.Errorf("Ended processing with %d left over bits.",
			bits.Size())
	}
	return root, nil
}

func (n *MerkleNode) matchedTransactions(txs *[][]byte) {
	if n == nil {
		return
	}
	if n.match {
		*txs = append(*txs, n.Hash)
	}
	n.Left.matchedTransactions(txs)
	n.Right.matchedTransactions(txs)
}

func (n *MerkleNode) MatchedTransactions() [][]byte {
	var txs [][]byte
	n.matchedTransactions(&txs)
	return txs
}

func (n *MerkleNode) Process(hashes *HashStack, bits *BitStack, levels int) error {
	flag := bits.Pop()
	if n.level < levels-1 {
		// non-txid
		if !flag {
			// Hash will be nil once we're out of hashes. nils will
			// be replaced by copies from their sibling.
			n.Hash = hashes.Pop()
			return nil
		}
	} else {
		// txid
		n.Hash = hashes.Pop()
		n.match = flag
		return nil
	}

	// non-txid and flag==1: Append child and compute hash from them.
	n.Left = &MerkleNode{
		level: n.level + 1,
		rank:  n.rank * 2,
	}
	err := n.Left.Process(hashes, bits, levels)
	if err != nil {
		return err
	}
	n.Right = &MerkleNode{
		level: n.level + 1,
		rank:  n.rank*2 + 1,
	}
	err = n.Right.Process(hashes, bits, levels)
	if err != nil {
		return err
	}
	if n.Left.Hash != nil {
		var hash []byte
		if n.Right.Hash != nil {
			hash = append(n.Left.Hash, n.Right.Hash...)
		} else {
			// Take left hash twice.
			hash = append(n.Left.Hash, n.Left.Hash...)
		}
		n.Hash = utils.DoubleHash(hash)
	} else {
		return fmt.Errorf("Left child (%d,%d) has nil hash.",
			n.Left.level, n.Left.rank)
	}
	return nil
}

type BitStack struct {
	Bytes []byte
	Next  int
}

func (s *BitStack) Size() int {
	return len(s.Bytes)*8 - s.Next
}

func (s *BitStack) Pop() bool {
	b := bit(s.Bytes, s.Next)
	s.Next++
	return b
}

type HashStack struct {
	Hashes [][]byte
	Next   int
}

func (s *HashStack) Size() int {
	return len(s.Hashes) - s.Next
}

func (s *HashStack) Pop() []byte {
	if s.Size() < 1 {
		return nil
	}
	hash := s.Hashes[s.Next]
	s.Next++
	return hash
}

func merkleTreeLevels(count uint32) int {
	if count == 0 {
		return 0
	}
	levels, i := 0, count-1
	for i > 0 {
		levels++
		i >>= 1
	}
	return levels + 1
}

func bit(flags []byte, i int) bool {
	by := i / 8
	bi := uint(i % 8)
	if by >= len(flags) {
		return false
	}
	return !((flags[by] & (1 << bi)) == 0)
}
