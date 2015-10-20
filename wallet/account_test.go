package wallet

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/aarbt/bitcoin-base58"
	"github.com/aarbt/bitcoin-wallet/messages"
	"github.com/aarbt/bitcoin-wallet/script"
	"github.com/aarbt/bitcoin-wallet/utils"
)

type MockInventory struct {
	inv map[string]*messages.Transaction
}

func NewMockInventory() *MockInventory {
	tx1, _ := hex.DecodeString("0100000001ca9b66c45ab5d802eff79224806a2bdcd690309a4dfcd8650963d3cd606ceadf000000006b4830450220324de09f8f7c8908d4a4b99c13aa28d1a5b3b680a196e6e6d39255e2b4d126c802210089fed6635be470c33f717db1a44f89150ebad18ab511fcf176c959cef7a9c9420121032d9850b19296fe1077f28a3c64d957f5242367dc6d42595b7ca7ca1aaed3dd1dffffffff0250c30000000000001976a914fe2927160e030613c119fbc68bc9ab0576f5911888ace0220200000000001976a9145ee70c467c5b2c35d2d08ef0d6d202b9c917b26188ac00000000")
	tx2, _ := hex.DecodeString("010000000194db6f49d474a9522dca43d0d83fc243049ed15600b07be4a568a377a590358b000000006a473044022023b2d60ad177429271d5df08a228e43ae3d60b63a236ed271b539dd7a391a6f102204e49ff80f5d6e06274fcac83e99371a7e324ecb08efd631ffb6f6f8c5889189a0121026db91d30b5e4081e02ff952f8d6b4d5e4528bd6617ae02a9abd7a437af0b6c2cffffffff02400d0300000000001976a91466fb2649c17e60c4cd16a05c903a161a24aa11a688acf3005f02000000001976a9143f896aad85d7fd306348c5f650662ed9346b2d6788ac00000000")
	parsed1, err := messages.ParseTransaction(tx1)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse tx: %v", err))
	}
	parsed2, err := messages.ParseTransaction(tx2)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse tx: %v", err))
	}
	inv := &MockInventory{
		inv: make(map[string]*messages.Transaction),
	}
	inv.inv[string(parsed1.Hash())] = parsed1
	inv.inv[string(parsed2.Hash())] = parsed2
	return inv
}

func (inv *MockInventory) UnspentTxOutputs() []*messages.TxOutput {
	// TODO add some irrelevant output.
	var outputs []*messages.TxOutput
	for _, tx := range inv.inv {
		for _, output := range tx.Outputs {
			outputs = append(outputs, output)
		}
	}
	return outputs
}

func TestPayments(t *testing.T) {
	seed := "xprv9z29aRLQo4Gkn2z7XczXBDup2Nig8EvDCXV7wub6FnSe36UkakkEfTN4TZH9obaPj" +
		"7yn4Zh5P1JSRvnfXAi6riG9g8WqrZjzenkU9MHxy6g"
	account, err := NewAccount(seed)
	if err != nil {
		t.Fatalf("Failed to set up account", err)
	}

	mock := NewMockInventory()
	account.SetTxInventory(mock)

	pay := account.NewPayment()
	decoded, _, _ := base58.BitcoinCheckDecode("1QAsw4fsfq3MJdgiEGod3MxY9BY2EnTWEU")
	pay.AddOutput(decoded, 50000)
	err = pay.AddInputsAndFee(10000)
	if err != nil {
		t.Fatalf("Failed to add inputs to payment: %v", err)
	}
	err = pay.Sign()
	if err != nil {
		t.Fatalf("Failed to sign payment: %v", err)
	}
	transactions := pay.Transactions()
	if len(transactions) != 1 {
		t.Errorf("Bad number of transactions, got %d expected 1.",
			len(transactions))
	}
	tx := transactions[0]

	for index, input := range tx.Inputs {
		stack := script.Stack{}
		err = stack.Execute(input.Signature, nil)
		if err != nil {
			t.Fatalf("Failed to push signature: %v", err)
		}
		prev := input.PreviousOutput
		inputTx, found := mock.inv[string(prev.Hash)]
		if !found {
			t.Fatalf("Input tx %x not found in map.", prev.Hash)
		}
		subscript := inputTx.Outputs[prev.Index].Script

		data := &script.Data{
			Hasher: func(c uint32) []byte {
				return utils.DoubleHash(tx.SignSerialize(
					index, subscript, c))
			}}
		err = stack.Execute(inputTx.Outputs[prev.Index].Script, data)
		if err != nil {
			t.Fatalf("Failed to execute script: %v", err)
		}
		if !stack.CheckSuccess() {
			t.Errorf("Signature on input %d not valid.", index)
		}
	}
}
