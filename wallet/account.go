package wallet

import (
	"fmt"

	"github.com/aarbt/hdkeys"
	"github.com/aarbt/bitcoin-wallet/messages"
)

// TODO Keep track of confirmations.
// TODO Avoid panic on bad input.

type Address struct {
	key  *hdkeys.Key
	used bool
}

func NewAddress(key *hdkeys.Key) *Address {
	return &Address{key: key}
}

type Account struct {
	txInventory    UnspentTxOutputter
	addrMap        map[string]*Address
	recvAddrList   []string
	changeAddrList []string

	receive *hdkeys.Key
	change  *hdkeys.Key
}

// Storage object that gives unspent outputs, some of which may be spendable by
// a certain account.
type UnspentTxOutputter interface {
	UnspentTxOutputs() []*messages.TxOutput
}

func (a *Account) SetTxInventory(inv UnspentTxOutputter) {
	a.txInventory = inv
}

type spendable struct {
	output *messages.TxOutput
	key    *hdkeys.Key
}

// SpendableOutputs reads outputs from a central storage and returns the ones
// that are spendable by this acount.
func (a *Account) SpendableOutputs() []spendable {
	orgList := a.txInventory.UnspentTxOutputs()
	var list []spendable
	for _, unspent := range orgList {
		// Get the address hash paid by the output.
		hash := unspent.AddressHash()
		if hash != nil {
			addr, found := a.addrMap[string(hash)]
			if found {
				list = append(list, spendable{
					key:    addr.key,
					output: unspent,
				})
			}
		}
	}
	return list
}

func (a *Account) NewPayment() *Payment {
	outputTx := messages.Transaction{
		Version: 1,
	}
	return &Payment{
		account: a,
		tx:      &outputTx,
	}
}

func (a *Account) NextReceiveAddress() []byte {
	// TODO Make this faster and more reliable.
	var index uint32
	for _, addr := range a.recvAddrList {
		if a.addrMap[addr].used {
			index++
		}
	}
	next, err := a.receive.Child(index)
	if err != nil {
		panic(fmt.Sprintf("Failed to derive child: %v", err))
	}
	return next.PublicKeyHash()
}

func (a *Account) NextChangeAddress() []byte {
	// TODO Make this faster and more reliable.
	var index uint32
	for _, addr := range a.changeAddrList {
		if a.addrMap[addr].used {
			index++
		}
	}
	next, err := a.change.Child(index)
	if err != nil {
		panic(fmt.Sprintf("Failed to derive child: %v", err))
	}
	return next.PublicKeyHash()
}

func (a *Account) WatchObjects() [][]byte {
	var list [][]byte
	for hash, _ := range a.addrMap {
		list = append(list, []byte(hash))
	}
	return list
}

func NewAccount(seed string) (*Account, error) {
	key, err := hdkeys.ParseEncoded(seed)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse seed %q: %v", seed, err)
	}
	if key.IsPublic() {
		// TODO Add support for watch only.
		return nil, fmt.Errorf("No private key provided.")
	}
	a := Account{
		addrMap: make(map[string]*Address),
	}
	a.receive, err = key.Child(0)
	if err != nil {
		panic(fmt.Sprintf("Child derivation failed: %v", err))
	}
	a.change, err = key.Child(1)
	if err != nil {
		panic(fmt.Sprintf("Child derivation failed: %v", err))
	}

	// TODO Add more addresses as they are consumed.
	for i := uint32(0); i < 20; i++ {
		k, err := a.receive.Child(i)
		if err != nil {
			panic(fmt.Sprintf("Child derivation failed: %v", err))
		}
		addrHash := string(k.PublicKeyHash())
		a.addrMap[addrHash] = NewAddress(k)
		a.recvAddrList = append(a.recvAddrList, addrHash)

		k, err = a.change.Child(i)
		if err != nil {
			panic(fmt.Sprintf("Child derivation failed: %v", err))
		}
		addrHash = string(k.PublicKeyHash())
		a.addrMap[addrHash] = NewAddress(k)
		a.changeAddrList = append(a.changeAddrList, addrHash)
	}
	return &a, nil
}
