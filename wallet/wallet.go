package wallet

import (
	"fmt"
	"net/http"

	"github.com/aarbt/bitcoin-base58"
	"github.com/aarbt/hdkeys"
)

// TODO Keep track of confirmations.
// TODO Avoid panic on bad input.

type Wallet struct {
	accounts []*Account
}

func New(root *hdkeys.Key) *Wallet {
	// TODO support more than one account.
	//k, err := root.Chain("m/44'/0'/0'")
	//if err != nil {
	//	panic(fmt.Sprintf("Child derivation failed: %v", err))
	//}
	w := Wallet{}
	//a, err := NewAccount(k.SerializeEncode())
	seed := "xprv9z29aRLQo4Gkn2z7XczXBDup2Nig8EvDCXV7wub6FnSe36UkakkEfTN4TZH9obaPj" +
		"7yn4Zh5P1JSRvnfXAi6riG9g8WqrZjzenkU9MHxy6g"
	a, err := NewAccount(seed)
	if err != nil {
		panic(fmt.Sprintf("Account creation failed: %v", err))
	}
	w.accounts = append(w.accounts, a)
	return &w
}

// Pay from account0
func (w *Wallet) NewPayment() *Payment {
	// TODO add support for more than one account and more than one output.
	return w.accounts[0].NewPayment()
}

func (w *Wallet) SetTxInventory(inv UnspentTxOutputter) {
	// TODO add support for more than one account.
	w.accounts[0].SetTxInventory(inv)
}

func (w *Wallet) MarkAddressAsUsed(hash []byte) {
	for _, a := range w.accounts {
		a.MarkAddressAsUsed(hash)
	}
}

func (w *Wallet) WatchObjects() [][]byte {
	var list [][]byte
	for _, a := range w.accounts {
		list = append(list, a.WatchObjects()...)
	}
	return list
}

func (w *Wallet) HasNewAddressesToWatch() bool {
	var b bool
	// TODO Potentially add watch of new accounts here.
	for _, a := range w.accounts {
		if a.HasNewAddressesToWatch() {
			b = true
		}
	}
	return b
}

func (wallet *Wallet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	// TODO support more than one account.
	a := wallet.accounts[0]
	fmt.Fprintf(w, "\n<p>Receive addresses:</p>\n")
	nextReceive := a.NextReceiveAddress()
	for _, h := range a.recvAddrList {
		encoded, _ := base58.BitcoinCheckEncode(
			base58.BitcoinPublicKeyHashPrefix, []byte(h))
		if h == string(nextReceive) {
			fmt.Fprintf(w, "<b>  %s\n</b><br>", encoded)
		} else {
			fmt.Fprintf(w, "  %s\n<br>", encoded)
		}
	}
	fmt.Fprintf(w, "\n<p>Change addresses:</p>\n")
	nextChange := a.NextChangeAddress()
	for _, h := range a.changeAddrList {
		encoded, _ := base58.BitcoinCheckEncode(
			base58.BitcoinPublicKeyHashPrefix, []byte(h))
		if h == string(nextChange) {
			fmt.Fprintf(w, "<b>  %s\n</b><br>", encoded)
		} else {
			fmt.Fprintf(w, "  %s\n<br>", encoded)
		}
	}
}
