package wallet

import (
	"fmt"

	"github.com/aarbt/bitcoin-wallet/messages"
	"github.com/aarbt/bitcoin-wallet/script"
	"github.com/aarbt/bitcoin-wallet/utils"
	"github.com/aarbt/hdkeys"
)

type Payment struct {
	account      *Account
	tx           *messages.Transaction
	transactions []*messages.Transaction
	keys         []*hdkeys.Key
}

func (p *Payment) Transactions() []*messages.Transaction {
	return p.transactions
}

func duplicateCountNeeded(list []*spendable, amount uint64) int {
	moreSplits := true
	for i := 1; i < 10 && moreSplits; i++ {
		var total uint64
		moreSplits = false
		for _, spend := range list {
			if len(spend.outputs) <= i {
				// Assuming all duplicates have same value.
				total += spend.outputs[0].Value
			}
			if len(spend.outputs) > i {
				moreSplits = true
			}
		}
		if total >= amount {
			return i
		}
	}
	return -1
}

// AddInputsAndFee to payment adds spendable inputs from the account until
// the value of the inputs matches or surpases the outputs. If the inputs
// become larger than the outputs, a change output from the account is added.
// No more outputs should be added after calling this.
func (p *Payment) AddInputsAndFee(fee uint64) error {
	a := p.account
	required := fee
	for _, outs := range p.tx.Outputs {
		required += outs.Value
	}
	// Get a list of unspent outputs that this account can spend.
	spendables := a.SpendableOutputs()

	count := duplicateCountNeeded(spendables, required)
	if count <= 0 {
		return fmt.Errorf("No enough funds to send: %d", required)
	}
	for i := 0; i < count; i++ {
		// Make a new copy of the transaction we've set up so far,
		// including all outputs.
		tx := *p.tx

		// Add inputs to transaction until it has enough.
		var total uint64
		for _, spend := range spendables {
			// For payments from multiple unconfirmed duplicates
			// we're assuming we only need splits from a single
			// duplicated transactions. If we end up using splits
			// from more than one, we'll be in a situation where we
			// rely on the splits with the same "index" gets
			// confirmed for all duplicated transactions.
			index := 0
			if len(spend.outputs) > 1 {
				index = i
			}
			output := spend.outputs[index]
			total += output.Value
			tx.AddInput(&messages.TxInput{
				PreviousOutput: &messages.OutPoint{
					Hash:  []byte(output.TxHash()),
					Index: output.Index(),
				},
				Sequence: 0xffffffff,
				// Temporarily store the subscript needed to
				// sign tx in signature.
				Signature: output.Script,
			})

			// Add keys in same order as inputs are added. This is
			// a bit hacky, but works since we control the order
			// the transactions are signed.
			p.keys = append(p.keys, spend.key)
			if total >= required {
				break
			}
		}
		if total > required {
			// Add change output for the excess satoshis.
			s, err := script.PayToPubKeyHash(a.NextChangeAddress())
			if err != nil {
				return fmt.Errorf("Failed to add change output: %v", err)
			}
			tx.AddOutput(&messages.TxOutput{
				Value:  total - required,
				Script: s,
			})
		}
		// Append completed transaction to list.
		p.transactions = append(p.transactions, &tx)
	}
	return nil
}

// AddOutput adds a standard pay to public key hash output to a payment transaction.
func (p *Payment) AddOutput(addrHash []byte, value uint64) error {
	s, err := script.PayToPubKeyHash(addrHash)
	if err != nil {
		return err
	}
	p.tx.AddOutput(&messages.TxOutput{
		Value:  value,
		Script: s,
	})
	return nil
}

// AddDataOutput adds up to 40 bytes of arbitrary data using the OP_RETURN op code.
func (p *Payment) AddDataOutput(data []byte) error {
	s, err := script.ArbitraryData(data)
	if err != nil {
		return err
	}
	p.tx.AddOutput(&messages.TxOutput{
		Script: s,
	})
	return nil
}

// Sign all the inputs of the payment transaction.
func (p *Payment) Sign() error {
	j := 0
	for _, tx := range p.transactions {
		for i, input := range tx.Inputs {
			// These keys were appended in the order of the
			// transactions and inputs, so they should correspond
			// to the addresses of the inputs.
			key := p.keys[j]
			hashCode := messages.SigTypeAll

			// Subscript is temporarily stored in signature field.
			data := utils.DoubleHash(tx.SignSerialize(
				i, input.Signature, uint32(hashCode)))
			r, s := key.Sign(data)
			input.Signature = script.SigScriptEncode(
				append(utils.DEREncode(r, s), byte(hashCode)), key.PublicKey())
			j++
		}
	}
	return nil
}
