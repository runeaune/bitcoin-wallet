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
	headers      *HeaderGetter

	connEstablished chan struct{}
	connected       bool
	confedEndpoints map[string]bool
}

type Config struct {
	Wallet   *wallet.Wallet
	Database *database.DB
	Network  Network
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

type Network interface {
	SendChannel() chan<- network.Message
	EndpointMisbehaving(string, int, string)
	EndpointsByQuality() []string
	Connected() chan struct{}
}

func New(config *Config) *Inventory {
	inv := Inventory{
		// TODO figure out a better way to avoid dropping messages.
		input:           make(chan network.Message, 2000),
		closeCh:         make(chan struct{}),
		doneCh:          make(chan struct{}),
		outputs:         make(map[string]*TxOutput),
		filter:          NewFilter(),
		config:          config,
		connEstablished: make(chan struct{}),
		confedEndpoints: make(map[string]bool),
	}

	if config == nil || config.Network == nil {
		log.Printf("Requires a network.")
		return nil
	}
	inv.output = config.Network.SendChannel()

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
	if config.Database != nil {
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

	inv.headers = GetHeaders(&inv, config.Database)
	return &inv
}

// Connected returns a channel that closes once an initial connection has been
// established.
func (inv *Inventory) Connected() chan struct{} {
	return inv.connEstablished
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

type dispatcher interface {
	Subscribe(string, chan<- network.Message)
	Unsubscribe(string)
}

func (inv *Inventory) Subscribe(d dispatcher) {
	d.Subscribe("block", inv.input)
	d.Subscribe("inv", inv.input)
	d.Subscribe("merkleblock", inv.input)
	d.Subscribe("tx", inv.input)
	d.Subscribe("version", inv.input)

	d.Subscribe("headers", inv.headers.Input())
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

func (inv *Inventory) Send(m network.Message) string {
	// TODO This function should send a message to a single endpoint (the
	// one perceived to be "best"), but if no response is received within a
	// few seconds, it should move on and try the next one on the list
	// (updating the ratings of the first one).
	endpoints := inv.config.Network.EndpointsByQuality()
	for _, endpoint := range endpoints {
		if _, found := inv.confedEndpoints[endpoint]; found {
			m.Endpoint = endpoint
			inv.output <- m
			return endpoint
		}
	}
	log.Printf("Trying to Send, but there are no configured endpoints.")
	return ""
}

// TODO Add headergetter function getting N most recent headers.
func (inv *Inventory) GetRecentMerkleBlocks(count int) error {
	// TODO avoid races with fetches of new blocks and updates of the
	// height.
	hash, height := inv.headers.highestKnownBlock()
	log.Printf("Fetching merkle blocks from height %d, and back %d blocks.",
		height, count)
	var vector messages.InventoryVector
	loc := hash
	for i := 0; i < count && loc != nil; i++ {
		vector = append(vector, &messages.Inventory{
			Type: messages.TypeMsgFilteredBlock,
			Hash: loc,
		})
		header := inv.headers.loadHeader(loc)
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

// reportMisbehaviour makes the network layer aware that an endpoint did
// something bad. This will usually result in the endpoint being disconnected.
func (inv *Inventory) reportMisbehaviour(endpoint string, score int, desc string) {
	if inv.config.Network != nil {
		log.Printf("Reporting endpoint misbehaviour: endpoint %q: %s\n",
			endpoint, desc)
		inv.config.Network.EndpointMisbehaving(endpoint, score, desc)
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
		if i.Type == messages.TypeMsgTX {
			hash := string(i.Hash)
			data, found := inv.data[hash]
			if !found {
				data = NewData(i.Hash)
				inv.data[hash] = data
				vector = append(vector, i)
			}
			data.AddPeer(m.Endpoint)
		} else if i.Type == messages.TypeMsgBlock {
			extHeader := inv.headers.loadHeader(i.Hash)
			if extHeader == nil {
				i.Type = messages.TypeMsgFilteredBlock
				vector = append(vector, i)
			}
		}
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
		// TODO Consider delaying this until we're sure the filter is actually set.
		inv.confedEndpoints[m.Endpoint] = true

		// First connection established, report as connected.
		if !inv.connected {
			close(inv.connEstablished)
			inv.connected = true
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
		extHeader := inv.headers.loadHeader(block.Hash())
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
				inv.headers.Close()
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