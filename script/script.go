package script

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/ripemd160"

	"github.com/aarbt/bitcoin-base58"
	"github.com/aarbt/bitcoin-crypto/bitecdsa"
	"github.com/aarbt/bitcoin-crypto/bitelliptic"
	"github.com/aarbt/bitcoin-wallet/utils"
)

type OpCode byte

const (
	OP_0              = 0x00
	OP_LENGTH_1       = 0x01
	OP_LENGTH_MAX     = 0x4b
	OP_VERIFY         = 0x69
	OP_RETURN         = 0x6a
	OP_DUP            = 0x76
	OP_XOR            = 0x86
	OP_EQUAL          = 0x87
	OP_EQUALVERIFY    = 0x88
	OP_RIPEMD160      = 0xa6
	OP_HASH160        = 0xa9
	OP_CODESEPARATOR  = 0xab
	OP_CHECKSIG       = 0xac
	OP_CHECKSIGVERIFY = 0xad
)

func (o OpCode) String() string {
	switch o {
	case OP_0:
		return "OP_0"
	case OP_VERIFY:
		return "OP_VERIFY"
	case OP_RETURN:
		return "OP_RETURN"
	case OP_DUP:
		return "OP_DUP"
	case OP_RIPEMD160:
		return "OP_RIPEMD160"
	case OP_HASH160:
		return "OP_HASH160"
	case OP_EQUAL:
		return "OP_EQUAL"
	case OP_EQUALVERIFY:
		return "OP_EQUALVERIFY"
	case OP_CODESEPARATOR:
		return "OP_CODESEPARATOR"
	case OP_CHECKSIG:
		return "OP_CHECKSIG"
	case OP_CHECKSIGVERIFY:
		return "OP_CHECKSIGVERIFY"
	default:
		return fmt.Sprintf("0x%x ", o)
	}
}

const (
	StandardPayToPubKeyHash = 1
)

type Script struct {
	Type int
	Hash []byte
}

type Object struct {
	op   OpCode
	data []byte
	err  error
}

func (o Object) True() bool {
	if len(o.data) == 1 && o.data[0] == 1 {
		return true
	}
	return false
}

func (o Object) Data() []byte {
	return o.data
}

func (o Object) String() string {
	if o.Data() != nil {
		return hex.EncodeToString(o.Data())
	}
	return "no data"
}

type Stack struct {
	stack []Object
}

func (s *Stack) Push(o Object) {
	s.stack = append(s.stack, o)
}

func (s *Stack) PushBool(b bool) {
	o := Object{}
	if b {
		o.data = []byte{0x01}
	} else {
		o.data = []byte{0x00}
	}
	s.stack = append(s.stack, o)
}

func (s *Stack) CheckSuccess() bool {
	o, err := s.Peek()
	if err != nil {
		return false
	}
	return o.True()
}

func (s *Stack) Peek() (Object, error) {
	if len(s.stack) < 1 {
		return Object{}, fmt.Errorf("Stack empty.")
	}
	return s.stack[len(s.stack)-1], nil
}

func (s *Stack) PopData() ([]byte, error) {
	o, err := s.Pop()
	if err != nil {
		return nil, err
	}
	return o.Data(), nil
}

func (s *Stack) Pop() (Object, error) {
	o, err := s.Peek()
	if err != nil {
		return Object{}, err
	}
	s.stack = s.stack[0 : len(s.stack)-1]
	return o, nil
}

func (s Stack) String() string {
	var str string
	for i, o := range s.stack {
		str += o.String()
		if i < len(s.stack)-1 {
			str += "\n"
		}
	}
	return str
}

func ParseOneElement(r *bytes.Buffer) (Object, error) {
	o := Object{}
	b, err := r.ReadByte()
	if err != nil {
		return o, fmt.Errorf("Couldn't not read first byte: %v", err)
	}
	if b >= OP_LENGTH_1 && b <= OP_LENGTH_MAX {
		data := make([]byte, b)
		n, err := r.Read(data)
		if err != nil || n != len(data) {
			o.err = err
			return o, fmt.Errorf("Couldn't read data: %v", err)
		}
		o.data = data
	} else {
		o.op = OpCode(b)
	}
	return o, nil
}

type HashFunc func(hashType uint32) []byte

type Data struct {
	Hasher HashFunc
}

func (s *Stack) Execute(script []byte, data *Data) error {
	buf := bytes.NewBuffer(script)
	for i := 0; buf.Len() != 0; i++ {
		o, err := ParseOneElement(buf)
		if err != nil {
			return err
		}
		if o.Data() != nil {
			s.Push(o)
			continue
		}
		switch o.op {
		case OP_DUP:
			err = FuncOP_DUP(s)
		case OP_HASH160:
			err = FuncOP_HASH160(s)
		case OP_EQUAL:
			err = FuncOP_EQUAL(s)
		case OP_EQUALVERIFY:
			err = FuncOP_EQUALVERIFY(s)
		case OP_CHECKSIG:
			err = FuncOP_CHECKSIG(s, data)
		case OP_CHECKSIGVERIFY:
			err = FuncOP_CHECKSIGVERIFY(s, data)
		default:
		}
		if err != nil {
			return fmt.Errorf("Operation %s (#%d) failed: %v",
				o.op, i, err)
		}
	}
	return nil
}

func FuncOP_DUP(s *Stack) error {
	o, err := s.Peek()
	if err != nil {
		return err
	}
	s.Push(o)
	return nil
}

func RIPEMD160Hash(data []byte) []byte {
	first := sha256.Sum256(data)
	hasher := ripemd160.New()
	hasher.Write(first[:])
	return hasher.Sum(nil)
}

func FuncOP_HASH160(s *Stack) error {
	o, err := s.Pop()
	if err != nil {
		return err
	}
	o.data = RIPEMD160Hash(o.data)
	s.Push(o)
	return nil
}

func FuncOP_VERIFY(s *Stack) error {
	o, err := s.Pop()
	if err != nil {
		return err
	}
	if !o.True() {
		return fmt.Errorf("OP_VERIFY: not true.")
	}
	return nil
}

func FuncOP_EQUAL(s *Stack) error {
	o1, err := s.Pop()
	if err != nil {
		return err
	}
	o2, err := s.Pop()
	if err != nil {
		return err
	}
	// TODO make more generic
	if bytes.Equal(o1.data, o2.data) {
		s.PushBool(true)
	} else {
		s.PushBool(false)
	}
	return nil
}

func FuncOP_EQUALVERIFY(s *Stack) error {
	err := FuncOP_EQUAL(s)
	if err != nil {
		return err
	}
	return FuncOP_VERIFY(s)
}

func FuncOP_CHECKSIG(s *Stack, data *Data) error {
	if data == nil || data.Hasher == nil {
		return fmt.Errorf("Requires a hasher.")
	}
	pk, err := s.PopData()
	if err != nil {
		return err
	}
	x, y, err := utils.ParsePublicKey(pk)
	if err != nil {
		return fmt.Errorf("Failed to parse public key: %v", err)
	}
	pubKey := bitecdsa.PublicKey{bitelliptic.S256(), x, y}

	sn, err := s.PopData()
	if err != nil {
		return err
	}
	sign, hashCode := sn[:len(sn)-1], sn[len(sn)-1]
	R, S, err := utils.DERDecode(sign)
	if err != nil {
		return fmt.Errorf("Failed to parse signature: %v", err)
	}
	hash := data.Hasher(uint32(hashCode))
	if bitecdsa.Verify(&pubKey, hash, R, S) {
		s.PushBool(true)
	} else {
		s.PushBool(false)
	}
	return nil
}

func FuncOP_CHECKSIGVERIFY(s *Stack, data *Data) error {
	err := FuncOP_CHECKSIG(s, data)
	if err != nil {
		return err
	}
	return FuncOP_VERIFY(s)
}

func ParseScriptObject(script []byte) []Object {
	list := make([]Object, 0)
	buf := bytes.NewBuffer(script)
	for {
		o := Object{}
		b, err := buf.ReadByte()
		if err != nil {
			break
		}
		if b >= OP_LENGTH_1 && b <= OP_LENGTH_MAX {
			data := make([]byte, b)
			n, err := buf.Read(data)
			if err != nil || n != len(data) {
				o.err = err
				continue
			}
			o.data = data
		} else {
			o.op = OpCode(b)
		}
		list = append(list, o)
	}
	return list
}

// LastSplit splits the script on every occurance of opCode and returns the
// last part, not including the opCode.
func LastSplit(script []byte, opCode byte) []byte {
	splits := bytes.Split(script, []byte{opCode})
	return splits[len(splits)-1]
}

// StripOpCode will remove all occurences of opCode from the the script.
func StripOpCode(script []byte, opCode byte) []byte {
	out := make([]byte, 0, len(script))
	for _, b := range script {
		if b != opCode {
			out = append(out, b)
		}
	}
	return out
}

func ParseScript(script []byte) string {
	buf := bytes.NewBuffer(script)
	str := ""
	for {
		b, err := buf.ReadByte()
		if err != nil {
			break
		}
		if b >= OP_LENGTH_1 && b <= OP_LENGTH_MAX {
			data := make([]byte, b)
			n, err := buf.Read(data)
			if err != nil || n != len(data) {
				str += fmt.Sprintf("<%s> ", err)
				continue
			}
			addr, err := base58.BitcoinCheckEncode(
				base58.BitcoinPublicKeyHashPrefix, data)
			if err == nil {
				str += fmt.Sprintf("%s ", addr)
			} else {
				str += fmt.Sprintf("%x ", data)
			}
			continue
		}
		str += OpCode(b).String() + " "
	}
	return str
}

// ParseStandard parses standard payments scripts and returns true and the
// destination hash if the script is standard.
func ParseStandard(s []byte) []byte {
	if len(s) != 25 {
		return nil
	}
	if s[0] != OP_DUP || s[1] != OP_HASH160 {
		return nil
	}
	l := s[2]
	if l >= OP_LENGTH_1 && l <= OP_LENGTH_MAX {
		// nothing
	} else {
		return nil
	}
	if s[23] != OP_EQUALVERIFY || s[24] != OP_CHECKSIG {
		return nil
	}
	return s[3:23]
}

func PayToPubKeyHash(hash []byte) ([]byte, error) {
	if len(hash) != 20 {
		return nil, fmt.Errorf("Hash %x has unexpected length: %d",
			hash, len(hash))
	}
	s := make([]byte, 25)
	s[0] = OP_DUP
	s[1] = OP_HASH160
	s[2] = byte(len(hash))
	copy(s[3:23], hash)
	s[23] = OP_EQUALVERIFY
	s[24] = OP_CHECKSIG
	return s, nil
}

func ArbitraryData(data []byte) ([]byte, error) {
	if len(data) > 40 {
		return nil, fmt.Errorf("Data %x is too big at %d bytes.",
			data, len(data))
	}
	s := make([]byte, 2+len(data))
	s[0] = OP_RETURN
	s[1] = byte(len(data))
	copy(s[2:], data)
	return s, nil
}

func SigScriptEncode(sig, pubKey []byte) []byte {
	data := make([]byte, 2+len(sig)+len(pubKey))
	data[0] = byte(len(sig))
	copy(data[1:1+len(sig)], sig)
	data[1+len(sig)] = byte(len(pubKey))
	copy(data[2+len(sig):], pubKey)
	return data
}
