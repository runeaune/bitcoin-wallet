package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aarbt/bitcoin-base58"
	"github.com/aarbt/bitcoin-network"
	"github.com/aarbt/bitcoin-wallet/database"
	"github.com/aarbt/bitcoin-wallet/inventory"
	"github.com/aarbt/bitcoin-wallet/messages"
	"github.com/aarbt/bitcoin-wallet/wallet"
	"github.com/aarbt/hdkeys"
	"github.com/aarbt/mnemonic"
)

var peerFile = flag.String("peerfile", "",
	"local file for storing known peers between runs.")
var connections = flag.Int("connections", 3,
	"number of connections to aim for.")
var walletSeed = flag.String("wallet_seed", "",
	"String of words corresponding to a HD wallet seed mnemonic.")

func main() {
	flag.Parse()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)

	var i *inventory.Inventory
	var n *network.Network
	var d *network.Dispatcher
	output := make(chan network.Message)

	go func() {
		sig := <-sigs

		fmt.Println()
		fmt.Println(sig)

		t := time.NewTimer(2 * time.Second)
		go func() {
			_ = <-t.C
			log.Println("shut down timed out; forcing exit")
			os.Exit(2)
		}()

		i.Unsubscribe(d)
		i.Close()
		n.Close()
		d.Close()
		close(output)

		os.Exit(1)
	}()

	n = network.New(network.Config{
		DesiredConnections: *connections,
		PeerStorageFile:    *peerFile,
		SeedHostnames: []string{
			"bitseed.xf2.org",
			"dnsseed.bluematt.me",
			"seed.bitcoin.sipa.be",
			"dnsseed.bitcoin.dashjr.org",
			"seed.bitcoinstats.com",
		},
		OutputChannel: output,
	})

	config := inventory.Config{
		// TODO Set database path from parameter.
		Database: database.Open(),
		Network:  n,
	}
	if *walletSeed != "" {
		seed := mnemonic.SeedFromWordsPassword(
			strings.Split(*walletSeed, " "), "")
		key := hdkeys.NewMasterKey(seed)
		config.Wallet = wallet.New(key)
	}
	i = inventory.New(&config)
	if config.Wallet != nil {
		config.Wallet.SetTxInventory(i)
	}

	d = network.NewDispatcher(output)
	i.Subscribe(d)
	d.Run()
	i.Run()

	go func() {
		<-i.Connected()
		i.GetRecentMerkleBlocks(2000)
	}()

	sendPayment := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if config.Wallet != nil {
			var tx *messages.Transaction
			if txHex := r.FormValue("tx"); txHex != "" {
				txSer, err := hex.DecodeString(txHex)
				if err != nil {
					fmt.Fprintf(w, "Error parsing transaction hex %q: %v",
						txHex, err)
					return
				}
				tx, err = messages.ParseTransaction(txSer)
				if err != nil {
					fmt.Fprintf(w, "Error parsing transaction %x: %v",
						txSer, err)
					return
				}
			} else {

				addr, prefix, err := base58.BitcoinCheckDecode(r.FormValue("addr"))
				if err != nil || prefix != base58.BitcoinPublicKeyHashPrefix {
					fmt.Fprintf(w, "Error parsing addr %q: %v",
						r.FormValue("addr"), err)
					return
				}
				value, err := strconv.ParseUint(r.FormValue("value"), 10, 64)
				if err != nil {
					fmt.Fprintf(w, "Error parsing value %q: %v",
						r.FormValue("value"), err)
					return
				}
				payment := config.Wallet.NewPayment()
				err = payment.AddOutput(addr, value)
				if err != nil {
					fmt.Fprintf(w, "Error adding output: %v", err)
					return
				}
				err = payment.AddInputsAndFee(10000)
				if err != nil {
					fmt.Fprintf(w, "Error adding inputs: %v", err)
					return
				}
				err = payment.Sign()
				if err != nil {
					fmt.Fprintf(w, "Error signing transaction: %v", err)
					return
				}
				tx = payment.Transaction()
			}
			fmt.Fprintf(w, "<font face=\"courier\">Transaction: %s</font>",
				strings.Replace(tx.String(), "\n", "<br/>", -1))
			verified, err := i.VerifyTransaction(tx)
			if err != nil {
				fmt.Fprintf(w, "Error verifying transaction: %v", err)
				return
			}
			fmt.Fprintf(w, "<br><b>Signatures verified: %v</b>", verified)
			if r.FormValue("send") == "true" {
				n.SendChannel() <- network.Message{
					Type: "tx",
					Data: tx.Data(),
				}
				n.SendChannel() <- network.Message{
					Type: "mempool",
				}
			} else {
				fmt.Fprintf(w, "<br><br><a href=\"?tx=%x&send=true\">"+
					"Broadcast transaction</a>", tx.Data())
			}
		} else {
			fmt.Fprintf(w, "No wallet configured.")
		}
	}

	http.Handle("/peers", n)
	http.Handle("/inventory/", i)
	http.HandleFunc("/send/payment", sendPayment)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
