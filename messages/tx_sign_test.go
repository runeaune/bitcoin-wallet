package messages

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aarbt/bitcoin-wallet/script"
	"github.com/aarbt/bitcoin-wallet/utils"

	"testing"
)

// File containing test vectors (raw transactions -> hashes for various sig hash codes).
// From
// https://github.com/bitcoin/bitcoin/blob/master/src/test/data/sighash.json
// with the serialized transaction before hashing added to ease debugging.
const sigHashFile = "sighash.json.txt"

type SigHashTest struct {
	RawTx      []byte
	Script     []byte
	InputIndex int
	SigType    uint32
	Hash       []byte
	Serialized []byte
}

// TestSignatureSerialization test serialization for signing on numerous transactions.
func TestSignatureSerialization(t *testing.T) {
	vector := loadSigHashTestVector()
	if len(vector) < 500 {
		t.Errorf("Test vector is too short. Has length %d, expected at least 500.",
			len(vector))
	}
	for i, test := range vector {
		tx, err := ParseTransaction(test.RawTx)
		if err != nil {
			t.Errorf("Test %d: Failed to parse transaction %x: %v",
				i, test.RawTx, err)
			continue
		}

		ser := tx.SignSerialize(test.InputIndex,
			script.StripOpCode(test.Script, script.OP_CODESEPARATOR),
			test.SigType)
		if !bytes.Equal(ser, test.Serialized) {
			t.Errorf("Test %d: Serialized data mismatch: Got %x, expected %x.",
				ser, test.Serialized)
		}

		hash := utils.DoubleHash(ser)
		if !bytes.Equal(hash, test.Hash) {
			t.Errorf("Test %d: Hash mismatch: Got %x, expected %x.",
				hash, test.Hash)
		}
	}
}

func TestSignatureVerification(t *testing.T) {
	txBytes, _ := hex.DecodeString("01000000038e03f0110b8790a4631c84b3854eef28fd88d1862f3c0871f5733e47149744b4000000008a47304402202c6ea579f64a0d4210a764f1d54b54c0495483612c8083ae480df6fc1687c142022015f9a616234e7568c3568d9e2db9adbde175b9b225aa135ed028e52e9806072c014104a370925557a6c17333662d995ece865b34381b9f2ebe797ea43b2d64cee02fb9f2c6f265894292e42cfa9c072d1b84317e8b9c14f3121256464199e1b21f08a9ffffffff0612f85b4b92de7aff285b34773dce93e3f3d77e02b72b5f891f455ee13321bd000000008b483045022075390f48dcbd0c1be4841c164ff572f1cfa4354cae3b624e50fc86491bb7cab2022100adac1a2d3b679eda893907be94e6df4f44c623cce93908d1244446af9320c3a8014104274bcff66ca29190e1fac756861633317a4377185369ebe72434af8d9faf45e7440253ba1af44ae5f256a81260c4609eff42bde0de64bb499b950efeb443641effffffff47294e69aa3a5420ccea69981fc4ff2e6cc21f8d4bf4cc15600b7452bd223702000000008c493046022100d9ae3cce570d50b2f55fe0a7e76cddeef70ea2a3d92a107ad54b04f1cf874b1d0221009876236768f4130f870029807cfef631d31bd329917e8d04ceeeaae2e1356a80014104e190e9d19e830bee250256f2d5e74a95a918cf7bf18c0facb95f0faed9f9be9a6ad51b4ee4b2d05e1096a472bb4cb37a9abaad0b560cbf0f212b7649720e6c91ffffffff0100d76ed3450000001976a914c958c010dcbdc6547edfc1b5475c5d82848b854588ac00000000")
	tx, err := ParseTransaction(txBytes)
	if err != nil {
		t.Fatalf("Failed to parse tx: %v", err)
	}
	inputBytes, _ := hex.DecodeString("01000000016f6c020690af020cf8cbc72140d8a0619bef9fa53cda96f923ad0b51084ba67a000000008b4830450220699885581136adbc6d54eefeafa1706a8b364da844f1dcbf5694cd95ef6b1a60022100e6ddd90d12690abfe3dafbfa9f96c00f25e8add7c05dad249ecba1917c72c6260141047cbbd46195f1da4a121aaccb0281e30da78da92d160893ef4f0ef588ab97b934fcf3defdfa489c4b29f5ae2bcd2147bd19263d5bc5bc55d967101ad441e21382ffffffff0200e40b54020000001976a914e4eef00d11c0e25fcb9e198bf2352113801d858188ac00f2052a010000001976a9145ac9d46f61b54108b960de4bcfb692bf354de8dc88ac00000000")
	input, err := ParseTransaction(inputBytes)
	if err != nil {
		t.Fatalf("Failed to parse input: %v", err)
	}

	prevIndex := 0 // Input TX's output used as input.
	signIndex := 1 // Input we'll be signing.

	t.Logf("Output used %x %d", tx.Inputs[signIndex].PreviousOutput.Hash,
		tx.Inputs[signIndex].PreviousOutput.Index)
	t.Logf("Output script %x", input.Outputs[prevIndex].Script)
	t.Logf("Output script parsed %s", script.ParseScript(input.Outputs[prevIndex].Script))
	t.Logf("Output value %d", input.Outputs[prevIndex].Value)
	t.Logf("Input sign %x", tx.Inputs[signIndex].Signature)
	t.Logf("Input sign parsed %s", script.ParseScript(tx.Inputs[signIndex].Signature))

	output := input.Outputs[prevIndex]
	s := script.LastSplit(output.Script, script.OP_CODESEPARATOR)

	stack := script.Stack{}
	err = stack.Execute(tx.Inputs[signIndex].Signature, nil)
	if err != nil {
		t.Fatalf("Failed to push signature: %v", err)
	}
	t.Logf("Stack: %s", stack)
	data := &script.Data{
		Hasher: func(c uint32) []byte {
			return utils.DoubleHash(tx.SignSerialize(signIndex, s, c))
		}}
	err = stack.Execute(input.Outputs[prevIndex].Script, data)
	if err != nil {
		t.Fatalf("Failed to execute script: %v", err)
	}
	if !stack.CheckSuccess() {
		t.Errorf("Verification failed.")
	}
}

func getBytes(i interface{}) []byte {
	bytes, err := hex.DecodeString(i.(string))
	if err != nil {
		panic(fmt.Sprintf("Couldn't parse hex encoded bytes (%s): %v",
			i.(string), err))
	}
	return bytes
}

func loadSigHashTestVector() []SigHashTest {
	file, err := os.Open(sigHashFile)
	if err != nil {
		panic(err.Error())
	}
	dec := json.NewDecoder(file)

	var o [][]interface{}

	err = dec.Decode(&o)
	if err != nil {
		panic(err.Error())
	}

	var vector []SigHashTest
	for i, test := range o {
		if len(test) != 6 {
			if i != 0 {
				panic(fmt.Sprintf("Sig hash vector %d has bad length %d.",
					i, len(test)))
			} else {
				continue
			}
		}
		t := SigHashTest{
			RawTx:      getBytes(test[0]),
			Script:     getBytes(test[1]),
			InputIndex: int(test[2].(float64)),
			SigType:    uint32(test[3].(float64)),
			Hash:       utils.ReverseBytes(getBytes(test[4])),
			Serialized: getBytes(test[5]),
		}
		vector = append(vector, t)
	}
	return vector
}
