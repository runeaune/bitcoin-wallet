package messages

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"testing"
)

func TestBloomFilter(t *testing.T) {
	data, _ := hex.DecodeString("019f5b01d4195ecbc9398fbf3c3b1fa9" +
		"bb3183301d7a1fb3bd174fcfa40a2b65")
	f, _ := NewFilterLoad(2, 11)
	f.AddData(data)
	if !bytes.Equal(f.Filter, []byte{0xb5, 0x0f}) {
		t.Errorf("Bad bloom filter: got %x, expected b50f", f.Filter)
	}
	if !f.MayContain(data) {
		t.Errorf("False negative for data %x", data)
	}

	not, _ := hex.DecodeString("019f5b01d4195ecbc9398fbf3c3b1fa9" +
		"bb3183301d7a1fb3bd174fcfa40a2b64")
	if f.MayContain(not) {
		t.Errorf("Unexpected false positive for data %x", not)
	}
}

/*
func hexToInt(h string) *big.Int {
	H, err := hex.DecodeString(h)
	if err != nil {
		panic(fmt.Sprintf("Input %s isn't hex: %v", h, err))
	}
	return new(big.Int).SetBytes(H)
}
*/

func decodeReverseHex(s string) []byte {
	H, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("Input %s isn't hex: %v", s, err))
	}
	for i := 0; i < len(H)/2; i++ {
		H[i], H[len(H)-1-i] = H[len(H)-1-i], H[i]
	}
	return H
}

// Test vectors are from Bitcoin code test code:
// https://github.com/bitcoin/bitcoin/blob/master/src/test/bloom_tests.cpp
func TestTxMatching(t *testing.T) {
	tx1data, _ := hex.DecodeString("01000000010b26e9b7735eb6aabdf358bab62f9816a21b" +
		"a9ebdb719d5299e88607d722c190000000008b4830450220070aca44506c5cef3a16e" +
		"d519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8" +
		"fba71e5aef6405b8643ac4cb7cb3c462aced7f14711a0141046d11fee51b0e60666d5" +
		"049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eeef87e10a5cd336c19a84" +
		"565f80fa6c547957b7700ff4dfbdefe76036c339ffffffff021bff3d1100000000197" +
		"6a91404943fdd508053c75000106d3bc6e2754dbcff1988ac2f15de00000000001976" +
		"a914a266436d2965547608b9e15d9032a7b9d64fa43188ac00000000")
	tx1, err := ParseTransaction(tx1data)
	if err != nil {
		t.Fatalf("Failed to parse test data TX1.")
	}
	tx1hash := decodeReverseHex(
		"b4749f017444b051c44dfd2720e88f314ff94f3dd6d56d40ef65854fcd7fff6b")

	filter, _ := NewFilterLoad(10000, 50)
	filter.AddData(tx1hash)
	//	filter.AddData(tx1.Hash)
	if !tx1.MatchesFilter(filter) {
		t.Errorf("Filter didn't match TX1 hash.")
	}

	randomHash, _ := hex.DecodeString("00000009e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436")
	filter, _ = NewFilterLoad(10000, 50)
	filter.AddData(randomHash)
	if tx1.MatchesFilter(filter) {
		t.Errorf("Filter DID match random TX1 hash.")
	}

	inputSig, _ := hex.DecodeString("30450220070aca44506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8fba71e5aef6405b8643ac4cb7cb3c462aced7f14711a01")
	filter, _ = NewFilterLoad(10000, 50)
	filter.AddData(inputSig)
	if !tx1.MatchesFilter(filter) {
		t.Errorf("Filter didn't match TX1 input signature.")
	}

	inputPubKey, _ := hex.DecodeString("046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eeef87e10a5cd336c19a84565f80fa6c547957b7700ff4dfbdefe76036c339")
	filter, _ = NewFilterLoad(10000, 50)
	filter.AddData(inputPubKey)
	if !tx1.MatchesFilter(filter) {
		t.Errorf("Filter didn't match TX1 input pub key.")
	}

	outputAddress, _ := hex.DecodeString("04943fdd508053c75000106d3bc6e2754dbcff19")
	filter, _ = NewFilterLoad(10000, 50)
	filter.AddData(outputAddress)
	if !tx1.MatchesFilter(filter) {
		t.Errorf("Filter didn't match TX1 output address.")
	}

	outputAddress2, _ := hex.DecodeString("a266436d2965547608b9e15d9032a7b9d64fa431")
	filter, _ = NewFilterLoad(10000, 50)
	filter.AddData(outputAddress2)
	if !tx1.MatchesFilter(filter) {
		t.Errorf("Filter didn't match second TX1 output address.")
	}

	badOutputAddress, _ := hex.DecodeString("04943fdd508053c75000106d3bc6e2754dbcff18")
	filter, _ = NewFilterLoad(10000, 50)
	filter.AddData(badOutputAddress)
	if tx1.MatchesFilter(filter) {
		t.Errorf("Filter DID match bad TX1 output address.")
	}
	// TODO test that spending tx is added to filter.

	outPoint := decodeReverseHex("90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b")
	outPoint = append(outPoint, []byte{0, 0, 0, 0}...)
	filter, _ = NewFilterLoad(10000, 50)
	filter.AddData(outPoint)
	if !tx1.MatchesFilter(filter) {
		t.Errorf("Filter didn't match TX1 out point.")
	}

	outPoint2 := decodeReverseHex("90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b")
	outPoint2 = append(outPoint2, []byte{1, 0, 0, 0}...)
	filter, _ = NewFilterLoad(10000, 50)
	filter.AddData(outPoint2)
	if tx1.MatchesFilter(filter) {
		t.Errorf("Filter DID match TX1 out point we don't care about.")
	}

	tx2data := []byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x6b, 0xff, 0x7f, 0xcd, 0x4f, 0x85,
		0x65, 0xef, 0x40, 0x6d, 0xd5, 0xd6, 0x3d, 0x4f, 0xf9, 0x4f, 0x31, 0x8f, 0xe8,
		0x20, 0x27, 0xfd, 0x4d, 0xc4, 0x51, 0xb0, 0x44, 0x74, 0x01, 0x9f, 0x74, 0xb4,
		0x00, 0x00, 0x00, 0x00, 0x8c, 0x49, 0x30, 0x46, 0x02, 0x21, 0x00, 0xda, 0x0d,
		0xc6, 0xae, 0xce, 0xfe, 0x1e, 0x06, 0xef, 0xdf, 0x05, 0x77, 0x37, 0x57, 0xde,
		0xb1, 0x68, 0x82, 0x09, 0x30, 0xe3, 0xb0, 0xd0, 0x3f, 0x46, 0xf5, 0xfc, 0xf1,
		0x50, 0xbf, 0x99, 0x0c, 0x02, 0x21, 0x00, 0xd2, 0x5b, 0x5c, 0x87, 0x04, 0x00,
		0x76, 0xe4, 0xf2, 0x53, 0xf8, 0x26, 0x2e, 0x76, 0x3e, 0x2d, 0xd5, 0x1e, 0x7f,
		0xf0, 0xbe, 0x15, 0x77, 0x27, 0xc4, 0xbc, 0x42, 0x80, 0x7f, 0x17, 0xbd, 0x39,
		0x01, 0x41, 0x04, 0xe6, 0xc2, 0x6e, 0xf6, 0x7d, 0xc6, 0x10, 0xd2, 0xcd, 0x19,
		0x24, 0x84, 0x78, 0x9a, 0x6c, 0xf9, 0xae, 0xa9, 0x93, 0x0b, 0x94, 0x4b, 0x7e,
		0x2d, 0xb5, 0x34, 0x2b, 0x9d, 0x9e, 0x5b, 0x9f, 0xf7, 0x9a, 0xff, 0x9a, 0x2e,
		0xe1, 0x97, 0x8d, 0xd7, 0xfd, 0x01, 0xdf, 0xc5, 0x22, 0xee, 0x02, 0x28, 0x3d,
		0x3b, 0x06, 0xa9, 0xd0, 0x3a, 0xcf, 0x80, 0x96, 0x96, 0x8d, 0x7d, 0xbb, 0x0f,
		0x91, 0x78, 0xff, 0xff, 0xff, 0xff, 0x02, 0x8b, 0xa7, 0x94, 0x0e, 0x00, 0x00,
		0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xba, 0xde, 0xec, 0xfd, 0xef, 0x05, 0x07,
		0x24, 0x7f, 0xc8, 0xf7, 0x42, 0x41, 0xd7, 0x3b, 0xc0, 0x39, 0x97, 0x2d, 0x7b,
		0x88, 0xac, 0x40, 0x94, 0xa8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9,
		0x14, 0xc1, 0x09, 0x32, 0x48, 0x3f, 0xec, 0x93, 0xed, 0x51, 0xf5, 0xfe, 0x95,
		0xe7, 0x25, 0x59, 0xf2, 0xcc, 0x70, 0x43, 0xf9, 0x88, 0xac, 0x00, 0x00, 0x00,
		0x00, 0x00}
	tx2, err := ParseTransaction(tx2data)
	if err != nil {
		t.Fatalf("Failed to parse test data TX2.")
	}
	// e2769b09e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436
	_ = tx2

}
