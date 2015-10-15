package inventory

import (
	"bytes"
	"encoding/hex"

	"testing"
)

func decode(data string) []byte {
	b, err := hex.DecodeString(data)
	if err != nil {
		panic(err.Error())
	}
	return b
}

func TestMerkleTreeLevelsCalculation(t *testing.T) {
	levels := []int{0, 1, 2, 3, 3, 4, 4, 4, 4, 5}
	for i, levels := range levels {
		if merkleTreeLevels(uint32(i)) != levels {
			t.Errorf("Wrong level calculation: count %d returned %d, expected %d",
				i, merkleTreeLevels(uint32(i)), levels)
		}
	}
}

// Test data is from https://bitcoin.org/en/developer-reference#parsing-a-merkleblock-message
func TestMerkleTreeGeneration1(t *testing.T) {
	rootHash := decode("7f16c5962e8bd963659c793ce370d95f093bc7e367117b3c30c1f8fdd0d97287")
	hashes := [][]byte{
		decode("3612262624047ee87660be1a707519a443b1c1ce3d248cbfc6c15870f6c5daa2"),
		decode("019f5b01d4195ecbc9398fbf3c3b1fa9bb3183301d7a1fb3bd174fcfa40a2b65"),
		decode("41ed70551dd7e841883ab8f0b16bf04176b7d1480e4f0af9f3d4c3595768d068"),
		decode("20d2a7bc994987302e5b1ac80fc425fe25f8b63169ea78e68fbaaefa59379bbf"),
	}
	flags := []byte{0x1d}
	root, err := NewMerkleTree(7, hashes, flags)
	if err != nil {
		t.Fatalf("Failed to process tree: %v", err)
	}
	if !bytes.Equal(root.Hash, rootHash) {
		t.Errorf("Merkle root mismatch: got %x, expected %x.", root.Hash, rootHash)
	}
	matches := root.MatchedTransactions()
	if len(matches) != 1 || !bytes.Equal(matches[0], hashes[1]) {
		t.Errorf("Merkle matched transactions: got %x, expected %x.", matches, hashes[1])
	}

}

// Test data is from block 000000000008fc72aaa5b691431cfcdeae16fbf59335f62ea768b8ec73189bff
// This is a block where almost half the tree is missing (72 out of 128 leaves)
// and right hashes need to be duplicates of the left ones.
func TestMerkleTreeGeneration2(t *testing.T) {
	rootHash := decode("6899a5dad5cdeddb2852d28cc69b7e39fc738016a92d2e96e6d31f8f1d50fd7a")
	hashes := [][]byte{
		decode("d6ce4bba4c952ea4f572096d67c5335174e98d9db5c271355c3906ddfc5b79eb"),
		decode("46e0fe892bb79ae9bcfc9aedf966b0e2ad226d44c0b9ee5d30873f92d4644226"),
		decode("957a11d28cb266e54f1d399e69eaeef3ca9f3353e230dd9f15c5c1f5ebef6aa8"),
		decode("858b1ad8c99fe9894b7f7ca45254fd9b0cf521e4590c7b461b161f2447d8cb5c"),
		decode("9f16fa62e89d440e3ebe74a21347a88cf8b7f37bd0b57f134c3e9e533fff263e"),
	}
	flags := []byte{0xfd, 0x01}
	root, err := NewMerkleTree(72, hashes, flags)
	if err != nil {
		t.Fatalf("Failed to process tree: %v", err)
	}
	if !bytes.Equal(root.Hash, rootHash) {
		t.Errorf("Merkle root mismatch: got %x, expected %x.", root.Hash, rootHash)
	}
	matches := root.MatchedTransactions()
	if len(matches) != 1 || !bytes.Equal(matches[0], hashes[1]) {
		t.Errorf("Merkle matched transactions: got %x, expected %x.", matches, hashes[1])
	}
}

// Test data is from block 00000000000004fc57db769ad321b2c056bb1894193fad72d44f07b2fe349d88
func TestMerkleTreeGeneration3(t *testing.T) {
	rootHash := decode("725bada5853bce138921c0c20e7e96e2d0af864458e6fdb165188db5a6d1dbaa")
	hashes := [][]byte{
		decode("482c5a148d00d0fc660c9ea5f5bd5eea4e8f8e088b054d3d0f5bda2fa43d4cfe"),
		decode("d2bfe408eb472664d2a3c1f398abfc3e5433851695943eee6a4d77a4c75e6eb5"),
		decode("90ec848a27bb43a5d79dfb9e0c59134fc2344ba01f309649c3c07052e3396095"),
		decode("8cf7b0b64631dd6575b6c2ac587feb4a477b6d7b6e98278b8c27f9d6b52dd5cb"),
		decode("bb4be3b5271cc45daf87710b7556a498d2b76c332f1bf70eab78047fb23ee0ef"),
		decode("feaec797b7b720c6cc9d7075eac67172babe31946ddf20589990c5203b45982a"),
	}
	flags := []byte{0x6d, 0x17}
	root, err := NewMerkleTree(171, hashes, flags)
	if err != nil {
		t.Fatalf("Failed to process tree: %v", err)
	}
	if !bytes.Equal(root.Hash, rootHash) {
		t.Errorf("Merkle root mismatch: got %x, expected %x.", root.Hash, rootHash)
	}
	matches := root.MatchedTransactions()
	if len(matches) != 1 || !bytes.Equal(matches[0], hashes[4]) {
		t.Errorf("Merkle matched transactions: got %x, expected %x.", matches, hashes[4])
	}
}
