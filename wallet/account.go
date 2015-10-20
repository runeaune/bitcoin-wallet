package wallet

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"sort"

	"github.com/aarbt/bitcoin-base58"
	"github.com/aarbt/bitcoin-wallet/messages"
	"github.com/aarbt/bitcoin-wallet/utils"
	"github.com/aarbt/hdkeys"
)

// How many addresses to scan in initial scan. Set this high to avoid extra
// scans for accounts with few transactions.
const kAddressInitialLimit = 15

// Assume no further addresses are used if encountering a sequence of this many
// unused ones.
const kAddressGapLimit = 5

// If less than kAddressGapLimit free addresses remain, fetch this many new ones.
const kAddressScanStep = 10

// TODO Keep track of confirmations.
// TODO Avoid panic on bad input.
// TODO Add mutex to avoid races.

type spendable struct {
	outputs []*messages.TxOutput
	key     *hdkeys.Key
}

type Address struct {
	key        *hdkeys.Key
	used       bool
	spendables []*spendable
}

// Balance returns the unspent balance in the address. Assumes UpdateBalances
// has been called just prior.
func (a Address) Balance() uint64 {
	var total uint64
	for _, s := range a.spendables {
		total += s.outputs[0].Value
	}
	return total
}

func NewAddress(key *hdkeys.Key) *Address {
	return &Address{key: key}
}

type Account struct {
	txInventory    UnspentTxOutputter
	addrMap        map[string]*Address
	recvAddrList   []string // refers addrMap
	changeAddrList []string // refers addrMap

	receive *hdkeys.Key
	change  *hdkeys.Key

	hasNewAddresses bool
}

// Storage object that gives unspent outputs, some of which may be spendable by
// a certain account.
type UnspentTxOutputter interface {
	UnspentTxOutputs() []*messages.TxOutput
}

func (a *Account) SetTxInventory(inv UnspentTxOutputter) {
	a.txInventory = inv
}

type OutputsByTxHash []*messages.TxOutput

func (slice OutputsByTxHash) Len() int {
	return len(slice)
}

func (slice OutputsByTxHash) Less(i, j int) bool {
	return bytes.Compare(slice[i].TxHash(), slice[j].TxHash()) < 0
}

func (slice OutputsByTxHash) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

// SpendableOutputs reads outputs from a central storage and returns the ones
// that are spendable by this acount.
func (a *Account) SpendableOutputs() []*spendable {
	for _, addr := range a.addrMap {
		addr.spendables = addr.spendables[:0]
	}
	orgList := a.txInventory.UnspentTxOutputs()
	var list []*spendable
	// Using the map to group outputs belonging to duplicate versions of a
	// transaction.
	m := make(map[string]*spendable)
	for _, unspent := range orgList {
		// Get the address hash paid by the output.
		hash := unspent.AddressHash()
		if hash != nil {
			addr, found := a.addrMap[string(hash)]
			if found {
				id := string(unspent.Fingerprint())
				s, found := m[id]
				if !found {
					s = &spendable{
						key: addr.key,
					}
					m[id] = s
					list = append(list, s)
					addr.spendables = append(addr.spendables, s)
				}
				s.outputs = append(s.outputs, unspent)
			}
		}
	}
	for _, addr := range a.addrMap {
		for _, spend := range addr.spendables {
			sort.Sort(OutputsByTxHash(spend.outputs))
		}
	}
	return list
}

// UpdateBalances will update the list of spendable outputs and hence the
// balance of all active addresses.
func (a *Account) UpdateBalances() {
	a.SpendableOutputs()
}

// UnusedAddresses returne the number of unused addresses at the end of the
// address space currently watched, ie. not counting those in gaps.
func (a *Account) UnusedAddresses(list []string) int {
	for i := len(list) - 1; i >= 0; i-- {
		addr, found := a.addrMap[list[i]]
		if !found {
			panic(fmt.Errorf("Address from list not found in map: %s", list[i]))
		}
		if addr.used {
			return len(list) - i - 1
		}
	}
	return len(list)
}

func (a *Account) NextFree(list []string) *Address {
	unused := a.UnusedAddresses(list)
	if unused <= 0 {
		return nil
	}
	return a.addrMap[list[len(list)-unused]]
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
	addr := a.NextFree(a.recvAddrList)
	return addr.key.PublicKeyHash()
}

func (a *Account) NextChangeAddress() []byte {
	addr := a.NextFree(a.changeAddrList)
	return addr.key.PublicKeyHash()
}

func (a *Account) MarkAddressAsUsed(hash []byte) {
	addr, found := a.addrMap[string(hash)]
	if found {
		addr.used = true
	}
}

func (a *Account) WatchObjects() [][]byte {
	var list [][]byte
	for hash, _ := range a.addrMap {
		list = append(list, []byte(hash))
	}
	a.hasNewAddresses = false
	return list
}

const (
	generateReceive = 0
	generateChange  = 1
)

// generateAddresses generates count additional addresses and add them to the
// chosen list.
func (a *Account) generateAddresses(change int, count int) error {
	a.hasNewAddresses = true
	key := a.receive
	list := &a.recvAddrList
	if change > 0 {
		key = a.change
		list = &a.changeAddrList
	}
	initial := len(*list)
	for i := 0; i < count; i++ {
		k, err := key.Child(uint32(i + initial))
		if err != nil {
			return fmt.Errorf("Child derivation failed: %v", err)
		}
		addrHash := string(k.PublicKeyHash())
		a.addrMap[addrHash] = NewAddress(k)
		*list = append(*list, addrHash)
		log.Printf("Generated address: %x\n", addrHash)
	}
	return nil
}

// hasNewAddressesToWatch returns true if additional addresses has been added
// since last call of WatchObjects.
func (a *Account) HasNewAddressesToWatch() bool {
	if a.UnusedAddresses(a.recvAddrList) < kAddressGapLimit {
		a.generateAddresses(generateReceive, kAddressScanStep)
		a.hasNewAddresses = true
	}
	if a.UnusedAddresses(a.changeAddrList) < kAddressGapLimit {
		a.generateAddresses(generateChange, kAddressScanStep)
		a.hasNewAddresses = true
	}
	return a.hasNewAddresses
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
		return nil, fmt.Errorf("Child derivation failed: %v", err)
	}
	a.change, err = key.Child(1)
	if err != nil {
		return nil, fmt.Errorf("Child derivation failed: %v", err)
	}

	for j := 0; j <= 1; j++ {
		// 0 for receive, 1 for change.
		err := a.generateAddresses(j, kAddressInitialLimit)
		if err != nil {
			return nil, err
		}
	}
	return &a, nil
}

func (a *Account) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	a.UpdateBalances()
	fmt.Fprintf(w, "\n<p>Receive addresses:</p>\n")
	for i, name := range a.recvAddrList {
		addr := a.addrMap[name]
		encoded, _ := base58.BitcoinCheckEncode(
			base58.BitcoinPublicKeyHashPrefix, []byte(name))
		// TODO get account numnber right.
		fmt.Fprintf(w, "m/44'/0'/0'/0/%d: %s,  balance: %d\n<br>",
			i, encoded, addr.Balance())
		for _, s := range addr.spendables {
			fmt.Fprintf(w, "Spendable output from tx %x (fingerprint):<br>",
				s.outputs[0].TxFingerprint())
			for _, o := range s.outputs {
				fmt.Fprintf(w, "tx %x (hash, internal byte order) (index %d): "+
					"%d satoshi\n<br>",
					utils.ReverseBytes(o.TxHash()), o.Index(), o.Value)
			}
		}
	}
	fmt.Fprintf(w, "\n<p>Change addresses:</p>\n")
	for i, name := range a.changeAddrList {
		addr := a.addrMap[name]
		encoded, _ := base58.BitcoinCheckEncode(
			base58.BitcoinPublicKeyHashPrefix, []byte(name))
		// TODO get account numnber right.
		fmt.Fprintf(w, "m/44'/0'/0'/1/%d: %s,  balance: %d\n<br>",
			i, encoded, addr.Balance())
		for _, s := range addr.spendables {
			fmt.Fprintf(w, "Spendable output from tx %x (fingerprint):<br>",
				s.outputs[0].TxFingerprint())
			for _, o := range s.outputs {
				fmt.Fprintf(w, "tx %x (hash, internal byte order) (index %d): "+
					"%d satoshi\n<br>",
					utils.ReverseBytes(o.TxHash()), o.Index(), o.Value)
			}
		}
	}
}
