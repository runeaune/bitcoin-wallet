package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aarbt/bitcoin-network"
	"github.com/aarbt/hdkeys"
	"github.com/aarbt/mnemonic"
	"github.com/aarbt/bitcoin-wallet/database"
	"github.com/aarbt/bitcoin-wallet/inventory"
	"github.com/aarbt/bitcoin-wallet/wallet"
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

	output := make(chan network.Message)
	n := network.New(network.Config{
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
	}
	if *walletSeed != "" {
		seed := mnemonic.SeedFromWordsPassword(
			strings.Split(*walletSeed, " "), "")
		key := hdkeys.NewPrivateKey(seed)
		config.Wallet = wallet.New(key)
	}
	i := inventory.New(&config)
	if config.Wallet != nil {
		config.Wallet.SetTxInventory(i)
	}

	d := network.NewDispatcher(output)
	i.Subscribe(d)
	i.SetSendChannel(n.SendChannel())
	d.Run()
	i.Run()

	// TODO Trigger this on first connection established.
	go func() {
		time.Sleep(10 * time.Second)
		i.GetRecentMerkleBlocks(500)
	}()
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

	http.Handle("/peers", n)
	http.Handle("/inventory/", i)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
