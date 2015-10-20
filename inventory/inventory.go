package inventory

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aarbt/bitcoin-base58"
	"github.com/aarbt/bitcoin-network"
	"github.com/aarbt/bitcoin-wallet/messages"
	"github.com/aarbt/bitcoin-wallet/script"
	"github.com/aarbt/bitcoin-wallet/utils"
	"github.com/aarbt/bitcoin-wallet/wallet"
)

var kHighestKnownBlock = []byte("last header")

type Inventory struct {
	input        chan network.Message
	output       chan<- network.Message
	txHashes     map[string]*TxVersion   // maps from hash.
	transactions map[string]*Transaction // maps from id/fingerprint.
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

type Database interface {
	LoadAllTransactions() []*TxVersion
	StoreNewTransaction(*TxVersion)
	Set([]byte, interface{})
	Get([]byte, interface{}) error
	Close()
}

type Config struct {
	Wallet   *wallet.Wallet
	Database Database
	Network  Network
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
		input: make(chan network.Message, 2000),

		closeCh: make(chan struct{}),
		doneCh:  make(chan struct{}),

		txHashes:     make(map[string]*TxVersion),
		transactions: make(map[string]*Transaction),

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

	if config.Database != nil {
		inv.loadTransactions(config.Database)
	}
	// Loop until all addresses have been added to the filter. This might
	// need more than one round in situations where the database contains
	// transactions to addresses near the end of the initial address list.
	needLoading := true
	for needLoading {
		// Add objects relevant to the wallet to our filter.
		if config.Wallet != nil {
			for _, o := range config.Wallet.WatchObjects() {
				inv.filter.Watch(o, filterMayNeedUpdate)
			}
		}

		// Load known transactions from database.
		if config.Database != nil {
			// Add the transactions we're watching to the filter.
			for hash, version := range inv.txHashes {
				if version.Block != nil {
					inv.transactionVersionConfirmed(version)
				}
				if version.InvalidatedBy == nil {
					inv.filter.Watch([]byte(hash), filterMayNeedUpdate)
				}
			}
			// Create/update list of unspent tx outputs. This relies on the
			// filter being up-to-date.
			for _, version := range inv.txHashes {
				if version.InvalidatedBy == nil {
					// This might add new addresses to wallet.
					inv.UpdateTxOutputs(version)
				}
			}
		}
		if config.Wallet != nil {
			needLoading = config.Wallet.HasNewAddressesToWatch()
		} else {
			needLoading = false
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
// watching. It also alerts attached wallets about new transaction to aid their
// discovery process.
func (inv *Inventory) UpdateTxOutputs(version *TxVersion) error {
	// TODO protect against races.
	tx := version.tx
	if tx == nil {
		return fmt.Errorf("Input has no transaction associated with it.")
	}
	id := tx.Fingerprint()

	// Check if new transaction spends one of our unspent outputs.
	for _, i := range tx.Inputs {
		prev := i.PreviousOutput
		outputId := Fingerprint(prev.Hash, prev.Index)
		out, found := inv.outputs[string(outputId)]
		if found {
			//			log.Printf("Output %d of tx %x spent by input %d of tx %x.",
			//				prev.Index, out.TxHash(), index, tx.Hash())
			out.spentBy = tx
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
				// can spend, so add it to the list and let the
				// wallets filter out the ones they can spend.
				encoded, _ := base58.BitcoinCheckEncode(
					base58.BitcoinPublicKeyHashPrefix, addr)
				output := TxOutput{
					index:  uint32(index),
					output: o,
					tx:     version,
					id:     id,
				}
				log.Printf("Transaction hash %x pays address %s with output %x",
					utils.ReverseBytes(tx.Hash()), encoded, output.Fingerprint())
				inv.outputs[string(output.Fingerprint())] = &output
				outputs = append(outputs, &output)

				if inv.config.Wallet != nil {
					inv.config.Wallet.MarkAddressAsUsed(addr)
				}
			}
		}
	}

	// Check if we already know a transaction that spends the new outputs.
	for _, o := range outputs {
		for _, version := range inv.txHashes {
			t := version.tx
			if t == nil {
				continue
			}
			for _, i := range t.Inputs {
				prev := i.PreviousOutput
				if bytes.Equal(prev.Hash, o.TxHash()) && prev.Index == o.index {
					//					log.Printf("Output %x(%d) already spent by input %x(%d).",
					//						o.TxHash(), prev.Index, t.Hash(), index)
					o.spentBy = t
				}
			}
		}
	}
	return nil
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

func (inv *Inventory) transactionVersionConfirmed(conf *TxVersion) {
	if conf.Id() == nil {
		// Lacks body, no way to find duplicates.
		return
	}
	tx := inv.transactions[string(conf.Id())]
	for _, version := range tx.versions {
		if !bytes.Equal(version.Hash(), conf.tx.Hash()) {
			// TODO Invalidate any transactions with this one as input.
			txVersion, found := inv.txHashes[string(version.Hash())]
			if found && txVersion.InvalidatedBy == nil {
				txVersion.InvalidatedBy = conf.tx.Hash()
				inv.config.Database.StoreNewTransaction(txVersion)
				for index, _ := range version.Outputs {
					outputId := Fingerprint(version.Hash(), uint32(index))
					_, found := inv.outputs[string(outputId)]
					if found {
						delete(inv.outputs, string(outputId))
					}
				}
			}
		}
	}
}

// addTxBlock indicates that a transaction hash has been included in a block.
func (inv *Inventory) addTxBlock(hash []byte, block *Block) {
	version, found := inv.txHashes[string(hash)]
	if !found {
		// Hash seen in block before TX arrived.
		version = &TxVersion{Hash: hash}
		inv.txHashes[string(hash)] = version
	}
	if version.Block == nil {
		log.Printf("Adding block %x to transaction hash %x.",
			block.Hash, hash)
		version.Block = block
		inv.config.Database.StoreNewTransaction(version)
		inv.transactionVersionConfirmed(version)
	}
	if version.Id() != nil {
		tx := inv.transactions[string(version.Id())]
		if tx.block == nil {
			tx.block = block
		}
	}
	// Add hash to filter. Remote nodes will do the same, so there's
	// no need to update them.
	inv.filter.Watch(hash, filterNoUpdateNeeded)
}

func (inv *Inventory) addTxData(hash []byte, data *messages.Transaction) {
	version, found := inv.txHashes[string(hash)]
	if !found {
		id := data.Fingerprint()
		log.Printf("Adding transaction hash %x for transaction %x", hash, id)
		version = &TxVersion{Hash: hash, tx: data}
		inv.txHashes[string(hash)] = version
		inv.config.Database.StoreNewTransaction(version)
	} else if version.tx == nil {
		version.tx = data
		inv.config.Database.StoreNewTransaction(version)
		if version.Block != nil {
			// This tx was confirmed earlier, but couldn't
			// invalidate duplicates until now; confirm it again.
			inv.transactionVersionConfirmed(version)
		}
	}
	tx, found := inv.transactions[string(version.Id())]
	if !found {
		log.Printf("Adding hash %x to transaction %x", hash, version.Id())
		tx = &Transaction{
			id:        version.Id(),
			timestamp: time.Now(),
			versions:  make(map[string]*messages.Transaction),
			block:     version.Block,
		}
		inv.transactions[string(version.Id())] = tx
	} else if tx.block != nil {
		// Another version of this transaction has already been confirmed.
		return
	}
	tx.versions[string(hash)] = data
	inv.UpdateTxOutputs(version)

	// Add transaction to filter. Remote nodes will do the same, so there's
	// no need to update them.
	inv.filter.Watch(hash, filterNoUpdateNeeded)
	// TODO verify TX
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

func (inv *Inventory) SendGetData(vector messages.InventoryVector, addrHint string) error {
	if len(vector) > 0 {
		data, err := messages.EncodeInventoryVector(vector)
		if err != nil {
			return fmt.Errorf("Failed to encode getdata vector: %v", err)
		}
		if addrHint != "" {
			inv.output <- network.Message{
				Type:     "getdata",
				Data:     data,
				Endpoint: addrHint,
			}
		} else {
			inv.Send(network.Message{
				Type: "getdata",
				Data: data,
			})
		}
	}
	return nil
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
	// Add hashes of merkleblocks to vector, starting from most recent.
	for i := 0; i < count && loc != nil; i++ {
		vector = append(vector, &messages.Inventory{
			Type: messages.TypeMsgFilteredBlock,
			Hash: loc,
		})
		header, err := inv.headers.loadHeader(loc)
		if err != nil {
			log.Printf("Failed to load previous header number %d: %v",
				i, err)
			break
		}
		loc = header.PrevBlock
	}
	// Reverse order to get blocks in chronological order.
	for i := 0; i < len(vector)/2; i++ {
		vector[i], vector[len(vector)-i-1] = vector[len(vector)-i-1], vector[i]
	}
	return inv.SendGetData(vector, "")
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
	if !tx.MatchesFilter(inv.filter.Filter()) {
		log.Printf("Received transaction %x not matching the filter.", tx.Hash())

	} else {
		log.Printf("Received transaction %x matching the filter: %x", tx.Hash(), tx.Data())
	}
	inv.addTxData(tx.Hash(), tx)

	w := inv.config.Wallet
	if w != nil {
		if w.HasNewAddressesToWatch() {
			// A wallet has had its address space expand and we
			// need to add these new addresses to the filter and
			// unless we're certain this is a fresh transaction (as
			// opposed to a historic one), we need to rescan
			// history.
			for _, o := range w.WatchObjects() {
				inv.filter.Watch(o, filterMayNeedUpdate)
			}
			// TODO Decide whether or not to rescan history. This
			// can be done easily (but slowely) by setting height
			// back to 0.
		}
	}
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
			log.Printf("Received inventory message with tx: %x from %q", hash, m.Endpoint)
			version, found := inv.txHashes[hash]
			if !found {
				version = &TxVersion{
					Hash: i.Hash,
				}
				inv.txHashes[hash] = version
				vector = append(vector, i)
			}
			// TODO keep track of peers that have relayed inv messages.
			//data.AddPeer(m.Endpoint)
		} else if i.Type == messages.TypeMsgBlock {
			extHeader, _ := inv.headers.loadHeader(i.Hash)
			if extHeader == nil {
				i.Type = messages.TypeMsgFilteredBlock
				vector = append(vector, i)
			}
		}
	}
	inv.SendGetData(vector, m.Endpoint)
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
		height, err := inv.headers.getBlockHeight(block.PrevBlock)
		if err != nil {
			// TODO This indicates that we're not caught up yet,
			// which can be useful information if we're receiving
			// short header lists from a bad node.
			// TODO Send a getheaders request.
			log.Printf("Couldn't figure out height of block: %v", err)
		} else {
			// Only store block if we known the height.
			height += 1
			block.Height = height
			inv.config.Database.Set(block.Hash(), block)

			log.Printf("Received Merkleheaders for block %d", height)
			_, highest := inv.headers.highestKnownBlock()
			if height > highest {
				inv.headers.setHighestKnownBlock(block.Hash(), height)
				log.Printf("Updated highest known block.")
			}
		}
		// Store transactions even if we couldn't get correct height.
		// TODO Update height value once we figure it out.
		short := Block{
			Hash:      block.Hash(),
			Timestamp: time.Unix(int64(block.Timestamp), 0),
			Height:    int32(height),
		}
		// Attach block information to transactions
		for _, tx := range root.MatchedTransactions() {
			// TODO Check against local filter.
			inv.addTxBlock(tx, &short)
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
		list := make([]*Transaction, 0, len(inv.transactions))
		for _, tx := range inv.transactions {
			list = append(list, tx)
		}
		fmt.Fprintf(w, "Transactions (%d):<br>\n", len(list))
		//sort.Sort(DataListByTime(list))
		for _, tx := range list {
			fmt.Fprintf(w, "%x (%s)<br>\n", tx.id, tx.timestamp)
			i := 0
			for _, version := range tx.versions {
				fmt.Fprintf(w, "%d: <a href=\"tx/%x\">%x</a><br>\n",
					i, version.Hash(), version.Hash())
				i++
			}
		}
	} else if strings.HasPrefix(path, "tx") {
		w.Header().Set("Content-Type", "text/plain")
		key := path[len("tx/"):]
		fmt.Fprintf(w, "TX: %s\n", key)
		hash, _ := hex.DecodeString(key)
		version, found := inv.txHashes[string(hash)]
		if found {
			fmt.Fprintf(w, "%s\n\nRelayed by:\n", version.tx)
			//for _, peer := range inv.Peers() {
			//	fmt.Fprintf(w, "%s\n", peer)
			//}
		} else {
			fmt.Fprintf(w, "Couldn't find TX %q.", key)
		}
	}
}

func (inv *Inventory) VerifyTransaction(tx *messages.Transaction) (bool, error) {
	var inputValue, outputValue uint64
	for index, input := range tx.Inputs {
		stack := script.Stack{}
		err := stack.Execute(input.Signature, nil)
		if err != nil {
			return false, fmt.Errorf("Failed to push signature: %v", err)
		}
		prev := input.PreviousOutput
		d, found := inv.txHashes[string(prev.Hash)]
		if !found {
			return false, fmt.Errorf("Input tx %x not found in map.", prev.Hash)
		}
		inputTx := d.tx
		output := inputTx.Outputs[prev.Index]
		inputValue += output.Value

		data := &script.Data{
			Hasher: func(c uint32) []byte {
				return utils.DoubleHash(tx.SignSerialize(
					index, output.Script, c))
			}}
		err = stack.Execute(output.Script, data)
		if err != nil {
			return false, fmt.Errorf("Failed to execute script: %v", err)
		}
		if !stack.CheckSuccess() {
			return false, fmt.Errorf("Signature on input %d not valid.", index)
		}
	}
	for _, output := range tx.Outputs {
		outputValue += output.Value
	}
	if outputValue > inputValue {
		return false, fmt.Errorf("Outputs have higher value (%d) than inputs (%d).",
			outputValue, inputValue)
	}
	return true, nil
}
