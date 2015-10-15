package wallet

import (
	"fmt"

	"github.com/aarbt/hdkeys"
	"github.com/aarbt/bitcoin-wallet/messages"
	"github.com/aarbt/bitcoin-wallet/script"
	"github.com/aarbt/bitcoin-wallet/utils"
)

type Payment struct {
	account *Account
	tx      *messages.Transaction
	keys    []*hdkeys.Key
}

func (p *Payment) Transaction() *messages.Transaction {
	return p.tx
}

// AddInputsAndFee to payment adds spendable inputs from the account until
// the value of the inputs matches or surpases the outputs. If the inputs
// become larger than the outputs, a change output from the account is added.
// No more outputs should be added after calling this.
func (p *Payment) AddInputsAndFee(fee uint64) error {
	a := p.account
	tx := p.tx
	required := fee
	for _, outs := range tx.Outputs {
		required += outs.Value
	}
	// Get a list of unspent outputs that this account can spend.
	spendables := a.SpendableOutputs()
	// Add them as inputs to transaction until we have enough value.
	var total uint64
	for _, spend := range spendables {
		total += spend.output.Value
		tx.AddInput(&messages.TxInput{
			PreviousOutput: &messages.OutPoint{
				Hash:  []byte(spend.output.TxHash()),
				Index: spend.output.Index(),
			},
			Sequence: 0xffffffff,
			// Temporarily store the subscript needed to
			// sign tx in signature.
			Signature: spend.output.Script,
		})
		p.keys = append(p.keys, spend.key)
		if total >= required {
			break
		}
	}
	if total < required {
		return fmt.Errorf("Trying to send %d satoshis, but has only %d.",
			required, total)
	}
	if total > required {
		// Add change output for the excess satoshis.
		change := a.NextChangeAddress()
		tx.AddOutput(&messages.TxOutput{
			Value:  total - required,
			Script: script.PayToPubKeyHash(change),
		})
	}
	return nil
}

// AddOutputToPayment adds a standard pay to public key hash output to a payment transaction.
func (p *Payment) AddOutput(addrHash []byte, value uint64) {
	p.tx.AddOutput(&messages.TxOutput{
		Value:  value,
		Script: script.PayToPubKeyHash(addrHash),
	})
}

// Sign all the inputs of the payment transaction.
func (p *Payment) Sign() error {
	for i, input := range p.tx.Inputs {
		key := p.keys[i]
		hashCode := messages.SigTypeAll

		// Subscript is temporarily stored in signature field.
		data := utils.DoubleHash(p.tx.SignSerialize(
			i, input.Signature, uint32(hashCode)))
		r, s := key.Sign(data)
		input.Signature = script.SigScriptEncode(
			append(utils.DEREncode(r, s), byte(hashCode)), key.PublicKey())
	}
	return nil
}
