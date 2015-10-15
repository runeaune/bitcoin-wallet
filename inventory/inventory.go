package inventory

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/aarbt/bitcoin-base58"
	"github.com/aarbt/bitcoin-network"
	"github.com/aarbt/bitcoin-wallet/database"
	"github.com/aarbt/bitcoin-wallet/messages"
	"github.com/aarbt/bitcoin-wallet/utils"
	"github.com/aarbt/bitcoin-wallet/wallet"
)

var kHighestKnownBlock = []byte("last header")

type Config struct {
	Wallet   *wallet.Wallet
	Database *database.DB
}

type TxOutput struct {
	output  *messages.TxOutput
	index   uint32
	data    *Data
	spentBy *Data
}

func Fingerprint(hash []byte, i uint32) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, i)
	return append(hash, b.Bytes()...)
}

// Fingerprint returns a unique identifier of the output.
func (out *TxOutput) Fingerprint() []byte {
	return Fingerprint(out.data.Hash, out.index)
}

// TxHash returns the hash of the transaction the output belongs to.
func (out *TxOutput) TxHash() []byte {
	return out.data.Hash
}

type Inventory struct {
	input        chan network.Message
	output       chan<- network.Message
	data         map[string]*Data
	closeCh      chan struct{}
	doneCh       chan struct{}
	bestEndpoint string
	filter       *Filter
	config       *Config
	outputs      map[string]*TxOutput
}

func New(config *Config) *Inventory {
	inv := Inventory{
		// TODO figure out a better way to avoid dropping messages.
		input:   make(chan network.Message, 2000),
		closeCh: make(chan struct{}),
		doneCh:  make(chan struct{}),
		outputs: make(map[string]*TxOutput),
		filter:  NewFilter(),
		config:  config,
	}

	// Add objects relevant to the wallet to our filter.
	if config.Wallet != nil {
		w := config.Wallet.WatchObjects()
		for _, o := range w {
			encoded, _ := base58.BitcoinCheckEncode(
				base58.BitcoinPublicKeyHashPrefix, o)
			log.Printf("Watching %x %s", o, encoded)
			inv.filter.Watch(o, true)
		}
	}

	// Load known transactions from database.
	if config != nil && config.Database != nil {
		inv.data = LoadTransactions(config.Database)

		// TODO Remove spent transactions.

		// Add the transactions we're watching to the filter.
		for hash, _ := range inv.data {
			inv.filter.Watch([]byte(hash), true)
		}
		// Create/update list of unspent tx outputs. This relies on the
		// filter to be up-to-date.
		for _, data := range inv.data {
			inv.UpdateTxOutputs(data)
		}
	}
	return &inv
}

// UnspentTransactions returns a list of the current unspent transactions in
// the set Inventory is watching.
func (inv *Inventory) UnspentTxOutputs() []*messages.TxOutput {
	// TODO protect against races.

	var list []*messages.TxOutput
	for _, out := range inv.outputs {
		if out.spentBy == nil {
			list = append(list, out.output)
		}
	}
	return list
}

// UpdateTxOutputs updates the list of unspent transaction outputs Inventory is
// watching.
func (inv *Inventory) UpdateTxOutputs(data *Data) {
	// TODO protect against races.
	tx := data.TX

	// Check if new transaction spends one of our unspent outputs.
	for index, i := range tx.Inputs {
		prev := i.PreviousOutput
		id := Fingerprint(prev.Hash, prev.Index)
		out, found := inv.outputs[string(id)]
		if found {
			log.Printf("Output %d of tx %x spent by input %d of tx %x.",
				prev.Index, out.TxHash(), index, tx.Hash)
			out.spentBy = data
		}
	}

	var outputs []*TxOutput
	// Check if new transaction pays any of our addresses.
	for index, o := range tx.Outputs {
		addr := o.AddressHash()
		if addr != nil {
			if inv.filter.Match(addr) {
				// This is an exact match, but not just for
				// public address hashes. Either way, it's
				// highly likely that this is an output that we
				// can spend, so add it to the list.
				log.Printf("Transaction %x pays address %x", tx.Hash, addr)
				output := TxOutput{
					index:  uint32(index),
					output: o,
					data:   data,
				}
				inv.outputs[string(output.Fingerprint())] = &output
				outputs = append(outputs, &output)
			}
		}
	}

	// Check if we already know a transaction that spend the new outputs.
	for _, o := range outputs {
		for _, data := range inv.data {
			t := data.TX
			for index, i := range t.Inputs {
				prev := i.PreviousOutput
				if bytes.Equal(prev.Hash, o.TxHash()) && prev.Index == o.index {
					log.Printf("Output %x(%d) already spent by input %x(%d).",
						o.TxHash(), prev.Index, t.Hash, index)
					o.spentBy = data
				}
			}
		}
	}
}

func (inv *Inventory) Close() {
	close(inv.closeCh)
	<-inv.doneCh
}
func (inv *Inventory) SetSendChannel(output chan<- network.Message) {
	inv.output = output
}

type dispatcher interface {
	Subscribe(string, chan<- network.Message)
	Unsubscribe(string)
}

func (inv *Inventory) Subscribe(d dispatcher) {
	d.Subscribe("block", inv.input)
	d.Subscribe("headers", inv.input)
	d.Subscribe("inv", inv.input)
	d.Subscribe("merkleblock", inv.input)
	d.Subscribe("tx", inv.input)
	d.Subscribe("version", inv.input)
}

func (inv *Inventory) Unsubscribe(d dispatcher) {
	d.Unsubscribe("block")
	d.Unsubscribe("headers")
	d.Unsubscribe("inv")
	d.Unsubscribe("merkleblock")
	d.Unsubscribe("tx")
	d.Unsubscribe("version")
}

// TODO Clean up this function.
func (inv *Inventory) addDataToInventory(hash []byte,
	tx *messages.Transaction, block *database.Block) *Data {

	var save bool
	data, found := inv.data[string(hash)]
	if !found {
		log.Printf("Transaction %x added to inventory.\n", hash)
		data = NewData(hash)
		inv.data[string(hash)] = data
	}
	if tx != nil {
		if data.TX == nil {
			data.TX = tx
			save = true
			inv.UpdateTxOutputs(data)
		}
	}
	if block != nil {
		if data.Block == nil {
			data.Block = block
			save = true
		}
		// TODO Check that block hasn't changed.
	}
	if save && data.TX != nil {
		inv.config.Database.StoreNewTransaction(&database.Transaction{
			Data:  data.TX.Serialize(),
			Block: data.Block,
		})
	}
	inv.filter.Watch(hash, false)
	// TODO verify TX
	return data
}

func (inv *Inventory) getHeader(hash []byte) *messages.ExtendedHeader {
	header := &messages.ExtendedHeader{}
	err := inv.config.Database.Get(hash, header)
	if err != nil {
		log.Printf("Getting header failed: %v", err)
		return nil
	}
	return header
}

func (inv *Inventory) setHeight(m *messages.ExtendedHeader) (uint, error) {
	prev := inv.getHeader(m.PrevBlock)
	if prev != nil {
		m.Height = prev.Height + 1
		return m.Height, nil
	} else {
		block0, _ := hex.DecodeString(
			"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
		if bytes.Equal(m.PrevBlock, utils.ReverseBytes(block0)) {
			m.Height = 1
			return 1, nil
		}
		return 0, fmt.Errorf("Couldn't find prev block.")
	}
}

type databaseBlockHeight struct {
	Hash   []byte
	Height uint
}

func (inv *Inventory) highestKnownBlock() ([]byte, uint) {
	// TODO store in memory if no database is set.
	db := inv.config.Database
	last := databaseBlockHeight{}
	err := db.Get(kHighestKnownBlock, &last)
	if err != nil {
		log.Printf("Couldn't retrieve highest known block: %v", err)
		return make([]byte, 32), 0
	}
	return last.Hash, last.Height
}

func (inv *Inventory) setHighestKnownBlock(hash []byte, height uint) {
	inv.config.Database.Set(kHighestKnownBlock, databaseBlockHeight{
		Hash:   hash,
		Height: height,
	})
}

func (inv *Inventory) getMoreHeaders() {
	hash, height := inv.highestKnownBlock()
	msg := messages.GetBlocks{
		Version:  70001,
		HashStop: make([]byte, 32),
		Locators: [][]byte{hash},
	}
	loc := hash
	// Add 20 recent known headers with larger and larger gaps between them
	// as they get less recent (up to a step of 40 between the two least
	// recent ones.)
	for i := 0; i < 20 && loc != nil; i++ {
		for j := 0; j < i*2; j++ {
			header := inv.getHeader(loc)
			if header == nil {
				loc = nil
				break
			}
			loc = header.PrevBlock
		}
		if loc != nil {
			msg.Locators = append(msg.Locators, loc)
		}
	}
	var msgBytes bytes.Buffer
	msg.Serialize(&msgBytes)
	inv.Send(network.Message{
		Type: "getheaders",
		Data: msgBytes.Bytes(),
	})
	log.Printf("Getting more headers, starting from %x at height %d.\n",
		utils.ReverseBytes(hash), height)
}

func (inv *Inventory) Send(m network.Message) {
	// TODO This function should send a message to a single endpoint (the
	// one perceived to be "best"), but if no response is received within a
	// few seconds, it should move on and try the next one on the list
	// (updating the ratings of the first one).
	if inv.bestEndpoint != "" {
		m.Endpoint = inv.bestEndpoint
		inv.output <- m
	} else {
		log.Printf("Trying to Send without having a best endpoint set.")
	}
}

func (inv *Inventory) GetRecentMerkleBlocks(count int) error {
	// TODO avoid races with fetches of new blocks and updates of the
	// height.
	hash, height := inv.highestKnownBlock()
	log.Printf("Fetching merkle blocks from height %d, and back %d blocks.",
		height, count)
	var vector messages.InventoryVector
	loc := hash
	for i := 0; i < count && loc != nil; i++ {
		vector = append(vector, &messages.Inventory{
			Type: messages.TypeMsgFilteredBlock,
			Hash: loc,
		})
		header := inv.getHeader(loc)
		if header == nil {
			break
		}
		loc = header.PrevBlock
	}
	data, err := messages.EncodeInventoryVector(vector)
	if err != nil {
		return fmt.Errorf("Failed to encode getdata vector: %v", err)
	}
	inv.Send(network.Message{
		Type: "getdata",
		Data: data,
	})
	return nil
}

func (inv *Inventory) handleHeaders(m network.Message) {
	_, oldHeight := inv.highestKnownBlock()
	headers, err := messages.ParseHeaders(m.Data)
	if err != nil {
		log.Printf("Failed to parse headers: %v", err)
		return
	}
	log.Printf("Received %d headers from %s.\n",
		len(headers), m.Endpoint)
	var hash []byte
	var height uint
	var vector messages.InventoryVector
	for _, h := range headers {
		height, err = inv.setHeight(h)
		if err != nil {
			log.Printf("Received bad header %x from %s.",
				utils.ReverseBytes(h.Hash()), m.Endpoint)
			// TODO break connection.
			break
		}
		hash = h.Hash()
		inv.config.Database.Set(hash, h)
		vector = append(vector, &messages.Inventory{
			Type: messages.TypeMsgFilteredBlock,
			Hash: hash,
		})
	}
	if len(hash) != 0 && height > oldHeight {
		inv.setHighestKnownBlock(hash, height)
		log.Printf("Last header updated to %x (internal byte order), height is %d.",
			utils.ReverseBytes(hash), height)
	}
	if len(headers) >= 2000 {
		inv.getMoreHeaders()
	}
	if len(vector) > 0 {
		data, err := messages.EncodeInventoryVector(vector)
		if err != nil {
			log.Printf("Failed to encode getdata vector: %v", err)
			return
		}
		inv.Send(network.Message{
			Type: "getdata",
			Data: data,
		})
	}
}

func (inv *Inventory) handleTransaction(tx *messages.Transaction) {
	if !inv.filter.Match(tx.Hash) {
		log.Printf("Received transaction %x not matching the filter.", tx.Hash)

	}
	inv.addDataToInventory(tx.Hash, tx, nil)
}

func (inv *Inventory) handleInvMessage(m network.Message) {
	v, err := messages.ParseInventoryVector(m.Data)
	if err != nil {
		log.Printf("Failed to parse inventory vector: %v", err)
	}

	// Request data for unknown inventory objects.
	var vector messages.InventoryVector
	for _, i := range v {
		// We don't need to ask for blocks, as
		// we'll get the relevant transactions
		// in merkleblocks.
		if i.Type != messages.TypeMsgTX {
			// TODO Request block header and merkleblock here.
			return
		}
		hash := string(i.Hash)
		data, found := inv.data[hash]
		if !found {
			data = NewData(i.Hash)
			inv.data[hash] = data
			vector = append(vector, i)
		}
		data.AddPeer(m.Endpoint)
	}
	data, err := messages.EncodeInventoryVector(vector)
	if err != nil {
		log.Fatalf("Failed to encode getdata vector: %v", err)
	}
	inv.Send(network.Message{
		Type: "getdata",
		Data: data,
	})
}

func (inv *Inventory) handleVersionMessage(m network.Message) {
	if inv.output != nil {
		inv.output <- network.Message{
			Type:     "filterload",
			Endpoint: m.Endpoint,
			Data:     inv.filter.RemoteData(),
		}

		inv.output <- network.Message{
			Type:     "mempool",
			Endpoint: m.Endpoint,
		}
		if inv.bestEndpoint == "" {
			inv.bestEndpoint = m.Endpoint
			inv.getMoreHeaders()
		}
	}
}

func (inv *Inventory) handleMerkleBlock(m network.Message) {
	block, err := messages.ParseMerkleBlock(m.Data)
	if err != nil {
		log.Printf("Failed to parse merkleblock: %v", err)
		return
	}
	if len(block.Flags) > 1 || block.Flags[0] != 0x00 {
		log.Printf("Merkleblock %x flags %x",
			utils.ReverseBytes(block.Hash()),
			block.Flags)
		root, err := NewMerkleTree(block.TotalTXs,
			block.Hashes, block.Flags)
		if err != nil || !bytes.Equal(root.Hash, block.MerkleRoot) {
			log.Printf("Merkle hash mismatch!")
			for _, h := range block.Hashes {
				log.Printf("Input hashes: %x", h)
			}
			log.Printf("Calculated merkle hash %x, "+
				"expected %x. %d matched transactions.",
				root.Hash, block.MerkleRoot,
				len(root.MatchedTransactions()))
			// TODO handle this without panicking.
			panic(fmt.Sprintf("TotalTXs %d, Flags %x",
				block.TotalTXs, block.Flags))
		}
		extHeader := inv.getHeader(block.Hash())
		short := database.Block{
			Hash:      block.Hash(),
			Timestamp: time.Unix(int64(block.Timestamp), 0),
			Height:    uint32(extHeader.Height),
		}
		// Attach block information to transactions
		for _, tx := range root.MatchedTransactions() {
			// TODO Check against local filter.
			inv.addDataToInventory(tx, nil, &short)
		}
	}
}

func (inv *Inventory) Run() {
	go func() {
		for {
			select {
			case _ = <-inv.closeCh:
				inv.config.Database.Close()
				close(inv.doneCh)
				return
			case m, ok := <-inv.input:
				if !ok {
					log.Fatal("Inventory input channel closed.")
				}
				switch m.Type {
				case "version":
					inv.handleVersionMessage(m)
				case "inv":
					inv.handleInvMessage(m)
				case "tx":
					tx, err := messages.ParseTransaction(m.Data)
					if err != nil {
						log.Printf("Failed to parse transaction: %v", err)
					} else {
						inv.handleTransaction(tx)
					}
				case "headers":
					inv.handleHeaders(m)
				case "merkleblock":
					inv.handleMerkleBlock(m)
				default:
					log.Fatalf("Inventory input channel sent message of type %q.",
						m.Type)
				}
			}
		}
	}()
}

func (inv *Inventory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path[len("/inventory/"):]
	if path == "" {
		w.Header().Set("Content-Type", "text/html")
		list := make([]*Data, 0, len(inv.data))
		for _, data := range inv.data {
			list = append(list, data)
		}
		fmt.Fprintf(w, "Transactions (%d):<br>\n", len(list))
		sort.Sort(DataListByTime(list))
		for _, data := range list {
			fmt.Fprintf(w, "<a href=\"tx/%s\">%s</a><br>\n",
				hex.EncodeToString(data.Hash), data)
		}
	} else if strings.HasPrefix(path, "tx") {
		w.Header().Set("Content-Type", "text/plain")
		key := path[len("tx/"):]
		fmt.Fprintf(w, "TX: %s\n", key)
		hash, _ := hex.DecodeString(key)
		inv, found := inv.data[string(hash)]
		if found {
			fmt.Fprintf(w, "%s\n\nRelayed by:\n", inv.TX)
			for _, peer := range inv.Peers() {
				fmt.Fprintf(w, "%s\n", peer)
			}
		} else {
			fmt.Fprintf(w, "Couldn't find TX %q.", key)
		}
	}
}
