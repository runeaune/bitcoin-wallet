package messages

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"

	"github.com/aarbt/bitcoin-base58"
	"github.com/aarbt/bitcoin-wallet/script"
	"github.com/aarbt/bitcoin-wallet/utils"
)

const (
	SigTypeAll    = 1
	SigTypeNone   = 2
	SigTypeSingle = 3
	sigTypeMask   = 0x1f

	SigTypeAnyOneCanPay = 0x80
)

type Transaction struct {
	Version  uint32
	Inputs   []*TxInput
	Outputs  []*TxOutput
	LockTime uint32

	// The following parameters are calculated locally and are not in
	// protocol messages.
	hash        []byte
	data        []byte
	fingerprint []byte
}

// Fingerprint returns a fingerprint that is unique for each tx but doen't
// include the signatures (or other things that can be changed after broadcast).
func (t *Transaction) Fingerprint() []byte {
	if t.fingerprint == nil {
		t.fingerprint = utils.DoubleHash(t.SerializeWithoutSignature())
	}
	return t.fingerprint
}

func (t *Transaction) Data() []byte {
	if t.data == nil {
		t.data = t.Serialize()
	}
	return t.data
}

func (t *Transaction) Hash() []byte {
	if t.hash == nil {
		t.hash = utils.DoubleHash(t.Data())
	}
	return t.hash
}

func (t *Transaction) InputTransactions() [][]byte {
	list := make([][]byte, len(t.Inputs))
	for i, in := range t.Inputs {
		list[i] = in.PreviousOutput.Hash
	}
	return list
}

func (t *Transaction) HashInternal() string {
	r := utils.ReverseBytes(t.Hash())
	return fmt.Sprintf("%x (internal byte order)", r)
}

func (t *Transaction) AddInput(i *TxInput) {
	t.Inputs = append(t.Inputs, i)
}

func (t *Transaction) AddOutput(o *TxOutput) {
	t.Outputs = append(t.Outputs, o)
}

func (t *Transaction) Serialize() []byte {
	if t == nil {
		return []byte{0x00}
	}
	if t.data == nil {
		t.data = t.SignSerialize(-1, nil, 0)
	}
	return t.data
}

func (t *Transaction) SerializeWithoutSignature() []byte {
	b := new(bytes.Buffer)
	binary.Write(b, binary.LittleEndian, t.Version)
	WriteCompactUint(uint(len(t.Inputs)), b)
	for _, in := range t.Inputs {
		b.Write(in.SerializeWithoutSignature())
	}
	WriteCompactUint(uint(len(t.Outputs)), b)
	for _, o := range t.Outputs {
		b.Write(o.Serialize())
	}
	binary.Write(b, binary.LittleEndian, t.LockTime)
	return b.Bytes()
}

const (
	sequenceAsNormal = false
	sequenceNilled   = true
)

// TODO This function is only weakly related to the message aspect of a
// transaction, consider moving it somewhere else.
func (t *Transaction) SignSerialize(signInput int, subscript []byte, hashCode uint32) []byte {

	if t == nil {
		return []byte{0x00}
	}
	b := new(bytes.Buffer)
	binary.Write(b, binary.LittleEndian, t.Version)
	if hashCode&SigTypeAnyOneCanPay != 0 && len(t.Inputs) > 0 {
		WriteCompactUint(1, b)
		b.Write(t.Inputs[signInput].SignSerialize(subscript, sequenceAsNormal))
	} else {
		maybeNilSequence := sequenceAsNormal
		if hashCode&sigTypeMask == SigTypeSingle || hashCode&sigTypeMask == SigTypeNone {
			maybeNilSequence = sequenceNilled
		}
		WriteCompactUint(uint(len(t.Inputs)), b)
		for i, in := range t.Inputs {
			if signInput == i {
				b.Write(in.SignSerialize(subscript, sequenceAsNormal))
			} else if signInput >= 0 {
				b.Write(in.SignSerialize(nil, maybeNilSequence))
			} else {
				b.Write(in.Serialize())
			}
		}
	}
	if hashCode&sigTypeMask == SigTypeSingle {
		// Only sign the output corresponding to the signed input.
		// Earlier outputs are nilled, later ones are dropped.

		if signInput < len(t.Outputs) {
			WriteCompactUint(uint(signInput+1), b)
			for i := 0; i < signInput; i++ {
				b.Write(NilOutput.Serialize())
			}
			b.Write(t.Outputs[signInput].Serialize())
		} else {
			// TODO Properly handle the case where the
			// corresponding output doesn't exist.
			WriteCompactUint(uint(len(t.Outputs)), b)
			for _, _ = range t.Outputs {
				b.Write(NilOutput.Serialize())
			}
		}
	} else if hashCode&sigTypeMask == SigTypeNone {
		// Don't sign any outputs.
		WriteCompactUint(0, b)
	} else {
		WriteCompactUint(uint(len(t.Outputs)), b)
		for _, o := range t.Outputs {
			b.Write(o.Serialize())
		}
	}
	binary.Write(b, binary.LittleEndian, t.LockTime)
	if signInput >= 0 {
		// Only include hashCode when signing.
		binary.Write(b, binary.LittleEndian, hashCode)
	}
	return b.Bytes()
}

func (t *Transaction) MatchesFilter(filter *FilterLoad) bool {
	if filter.MayContain(t.Hash()) {
		return true
	}
	if filter.MayContain(utils.ReverseBytes(t.Hash())) {
		log.Printf("Tx matched reverse hash: %x", t.Hash)
		return true
	}
	for _, o := range t.Outputs {
		if o.MatchesFilter(filter) {
			return true
		}
	}
	for _, i := range t.Inputs {
		if i.MatchesFilter(filter) {
			return true
		}
	}
	return false
}

func (t *Transaction) String() string {
	str := fmt.Sprintf("%x, version %d\n\n",
		utils.ReverseBytes(t.Hash()), t.Version)
	for _, i := range t.Inputs {
		str += fmt.Sprintf("%s\n\n", i)
	}
	for _, o := range t.Outputs {
		str += fmt.Sprintf("%s\n", o)
	}
	str += fmt.Sprintf("\n")
	if t.LockTime == 0 {
		str += fmt.Sprintf("Unlocked.")
	} else {
		str += fmt.Sprintf("Locktime %d.", t.LockTime)
	}
	return str
}

type TxInput struct {
	PreviousOutput *OutPoint
	Signature      []byte
	Sequence       uint32

	// Internal variables not present in protocol message.
	tx *Transaction
}

func (i *TxInput) MatchesFilter(filter *FilterLoad) bool {
	if filter.MayContain(i.PreviousOutput.Serialize()) {
		return true
	}
	s := script.ParseScriptObject(i.Signature)
	for _, e := range s {
		if len(e.Data()) > 0 {
			if filter.MayContain(e.Data()) {
				return true
			}
		}
	}
	return false
}

func (i *TxInput) String() string {
	os := script.ParseScriptObject(i.Signature)
	str := fmt.Sprintf("Input: tx %s", i.PreviousOutput)
	if len(os) == 2 {
		hash := utils.RIPEMD160Hash(os[1].Data())
		addr, err := base58.BitcoinCheckEncode(
			base58.BitcoinPublicKeyHashPrefix, hash)
		if err != nil {
			str += fmt.Sprintf(" => %x", hash)
		} else {
			str += fmt.Sprintf(" => %s", addr)
		}
		str += fmt.Sprintf("\n  Signature: %x", os[0].Data())
	}
	return str
}

func (i *TxInput) Index() uint {
	return uint(i.PreviousOutput.Index)
}

// Serialize returns the serialized version of the input as described by the protocol.
func (i *TxInput) Serialize() []byte {
	b := &bytes.Buffer{}
	b.Write(i.PreviousOutput.Serialize())
	WriteVarBytes(i.Signature, b)
	binary.Write(b, binary.LittleEndian, i.Sequence)
	return b.Bytes()
}

// SignSerialize returns the serialized version of the input, as required for
// signing the transaction. If a subscript is provided, it will be put in the
// place of the signature, if not provided the signature field will be left
// empty. If nilSequence is true, the sequence number will be set to 0,
// otherwise left as-is.
func (i *TxInput) SignSerialize(subscript []byte, nilSequence bool) []byte {
	b := &bytes.Buffer{}
	b.Write(i.PreviousOutput.Serialize())
	if subscript != nil {
		WriteVarBytes(subscript, b)
	} else {
		WriteVarBytes([]byte{}, b)
	}
	if nilSequence {
		binary.Write(b, binary.LittleEndian, uint32(0))
	} else {
		binary.Write(b, binary.LittleEndian, i.Sequence)
	}
	return b.Bytes()
}

// SerializeWithoutSignature serializes the input, leaving the signature field
// empty. This is intended to just cover the fields not affected by transaction
// malleability.
func (i *TxInput) SerializeWithoutSignature() []byte {
	return i.SignSerialize(nil, false)
}

func parseTxInput(b io.Reader) (*TxInput, error) {
	var err error
	input := TxInput{}

	input.PreviousOutput, err = ParseOutPoint(b)
	if err != nil {
		return nil, fmt.Errorf("Could not read PreviousOutput field: %v", err)
	}
	input.Signature, err = ParseVarBytes(b)
	if err != nil {
		return nil, fmt.Errorf("Could not read signature field: %v", err)
	}
	err = binary.Read(b, binary.LittleEndian, &input.Sequence)
	if err != nil {
		return nil, fmt.Errorf("Could not read sequence field: %v", err)
	}
	return &input, nil
}

func (t *Transaction) parseTxInputs(b io.Reader) error {
	count, err := ParseCompactUint(b)
	if err != nil {
		return fmt.Errorf("Could not read count field: %v", err)
	}
	t.Inputs = make([]*TxInput, count)
	for i := uint(0); i < count; i++ {
		input, err := parseTxInput(b)
		if err != nil {
			return fmt.Errorf("Could not parse input number %d: %v", i, err)
		}
		input.tx = t
		t.Inputs[i] = input
	}
	return nil
}

type OutPoint struct {
	Hash  []byte
	Index uint32

	// Internal variables not included in protocol messages.
	data []byte
}

func (p OutPoint) String() string {
	return fmt.Sprintf("%x (output index %d)", utils.ReverseBytes(p.Hash), p.Index)
}

func (p *OutPoint) Serialize() []byte {
	if p.data == nil {
		b := &bytes.Buffer{}
		b.Write(p.Hash)
		binary.Write(b, binary.LittleEndian, p.Index)
		p.data = b.Bytes()
	}
	return p.data
}

func ParseOutPoint(input io.Reader) (*OutPoint, error) {
	// Tee stream to save the raw data.
	data := new(bytes.Buffer)
	b := io.TeeReader(input, data)

	var err error
	o := OutPoint{}
	o.Hash, err = ParseBytes(b, 32)
	if err != nil {
		return nil, fmt.Errorf("Could not read hash field: %v", err)
	}
	err = binary.Read(b, binary.LittleEndian, &o.Index)
	if err != nil {
		return nil, fmt.Errorf("Could not read index field: %v", err)
	}
	o.data = data.Bytes()
	return &o, nil
}

type TxOutput struct {
	Value  uint64
	Script []byte

	// Internal variables not part of the protocol message.
	addrHash []byte       // Address hash paid by (standard) script.
	tx       *Transaction // TX this output belongs to.
	index    uint32       // Index of this output.
}

// NilOutput is the nil value of an output and is used for nilling irrelevant
// outputs when signing.
var NilOutput = TxOutput{
	math.MaxUint64,
	nil,
	nil,
	nil,
	0,
}

func (o *TxOutput) String() string {
	return fmt.Sprintf("Output: %d satoshis (%f mBTC) to script: %s",
		o.Value, float64(o.Value)/1e5, script.ParseScript(o.Script))
}

func (o *TxOutput) MatchesFilter(filter *FilterLoad) bool {
	// TODO Speed this up.
	s := script.ParseScriptObject(o.Script)
	for _, e := range s {
		if len(e.Data()) > 0 {
			if filter.MayContain(e.Data()) {
				return true
			}
		}
	}
	return false
}

func (o TxOutput) Serialize() []byte {
	b := &bytes.Buffer{}
	binary.Write(b, binary.LittleEndian, o.Value)
	WriteVarBytes(o.Script, b)
	return b.Bytes()
}

// AddressHash returns the hash of the address being paid, or nil of the output
// is non-standard.
func (o TxOutput) AddressHash() []byte {
	return o.addrHash
}

// TxHash returns the hash of the transaction the output is a part of.
func (o TxOutput) TxHash() []byte {
	if o.tx != nil {
		return o.tx.Hash()
	} else {
		return []byte{0x00}
	}
}

func (o TxOutput) TxFingerprint() []byte {
	if o.tx != nil {
		return o.tx.Fingerprint()
	} else {
		return []byte{0x00}
	}
}

// Index returns the index of the output in its transaction.
func (o TxOutput) Index() uint32 {
	return o.index
}

// Fingerprint returns a unique identifier of the transaction (unique across
// modified versions) and the output.
func (o TxOutput) Fingerprint() []byte {
	b := &bytes.Buffer{}
	b.Write(o.TxFingerprint())
	binary.Write(b, binary.LittleEndian, o.index)
	return b.Bytes()
}

func ParseTxOutput(b io.Reader) (*TxOutput, error) {
	var err error
	o := TxOutput{}
	err = binary.Read(b, binary.LittleEndian, &o.Value)
	if err != nil {
		return nil, fmt.Errorf("Could not read value field: %v", err)
	}
	o.Script, err = ParseVarBytes(b)
	if err != nil {
		return nil, fmt.Errorf("Could not read script field: %v", err)
	}
	o.addrHash = script.ParseStandard(o.Script)
	return &o, nil
}

func (t *Transaction) parseTxOutputs(b io.Reader) error {
	count, err := ParseCompactUint(b)
	if err != nil {
		return fmt.Errorf("Could not read count field: %v", err)
	}
	t.Outputs = make([]*TxOutput, count)
	for i := uint(0); i < count; i++ {
		output, err := ParseTxOutput(b)
		if err != nil {
			return fmt.Errorf("Could not parse output number %d: %v", i, err)
		}
		output.tx = t
		output.index = uint32(i)
		t.Outputs[i] = output
	}
	return nil
}

func parseTransactionFromStreamWithoutHash(b io.Reader) (*Transaction, error) {
	var err error
	t := Transaction{}

	err = binary.Read(b, binary.LittleEndian, &t.Version)
	if err != nil {
		return nil, fmt.Errorf("Could not read version field: %v", err)
	}
	err = t.parseTxInputs(b)
	if err != nil {
		return nil, fmt.Errorf("Could not parse inputs: %v", err)
	}
	err = t.parseTxOutputs(b)
	if err != nil {
		return nil, fmt.Errorf("Could not parse outputs: %v", err)
	}
	err = binary.Read(b, binary.LittleEndian, &t.LockTime)
	if err != nil {
		return nil, fmt.Errorf("Could not read locktime field: %v", err)
	}
	return &t, nil
}

func ParseCoinbaseTransactionFromStream(input io.Reader) (*Transaction, error) {
	// Tee stream to a SHA256 hasher.
	hasher := sha256.New()
	b := io.TeeReader(input, hasher)

	t, err := parseTransactionFromStreamWithoutHash(b)
	if err != nil {
		return nil, err
	}

	// Complete hash calculation and add it to the transaction.
	first := hasher.Sum(nil)
	hash := sha256.Sum256(first[:])
	t.hash = hash[:]
	return t, nil
}

func ParseTransactionFromStream(input io.Reader) (*Transaction, error) {
	// Tee stream to save the raw data.
	data := new(bytes.Buffer)
	b := io.TeeReader(input, data)

	t, err := parseTransactionFromStreamWithoutHash(b)
	if err != nil {
		return nil, err
	}

	t.data = data.Bytes()
	t.hash = utils.DoubleHash(t.data)
	return t, nil
}

func ParseTransaction(data []byte) (*Transaction, error) {
	b := bytes.NewBuffer(data)
	t, err := parseTransactionFromStreamWithoutHash(b)
	if err != nil {
		return nil, err
	}
	t.data = data
	t.hash = utils.DoubleHash(data)
	return t, nil
}
