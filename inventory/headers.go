package inventory

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/aarbt/bitcoin-network"
	"github.com/aarbt/bitcoin-wallet/messages"
	"github.com/aarbt/bitcoin-wallet/utils"
)

type HeaderGetter struct {
	inv    *Inventory
	input  chan network.Message
	output chan *messages.ExtendedHeader
	db     Database

	closeCh chan struct{}
	doneCh  chan struct{}
}

func GetHeaders(inv *Inventory, db Database) *HeaderGetter {
	getter := HeaderGetter{
		inv: inv,
		db:  db,

		closeCh: make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
	getter.Run()
	return &getter
}

// Close shuts down the header getter. It is guaranteed to not read or write to
// any channels after Close returns.
func (getter *HeaderGetter) Close() {
	close(getter.closeCh)
	<-getter.doneCh
}

func (getter *HeaderGetter) Run() {
	go func() {
		var closing bool
		for !closing {
			timer := time.NewTimer(2 * time.Minute)
			incomplete := getter.requestMoreHeaders()
			if !incomplete {
				// We shouldn't need to poll for headers very
				// often as blocks are broadcast by miners.
				select {
				case <-timer.C:
					//nothing
				case <-getter.closeCh:
					closing = true
					break
				}
			}
		}
		close(getter.doneCh)
	}()
}

func (getter *HeaderGetter) Input() chan<- network.Message {
	// TODO Find a better way to avoid dropped messages.
	getter.input = make(chan network.Message, 10)
	return getter.input
}

func (getter *HeaderGetter) loadHeader(hash []byte) (*messages.ExtendedHeader, error) {
	header := &messages.ExtendedHeader{}
	err := getter.db.Get(hash, header)
	if err != nil {
		return nil, fmt.Errorf("Loading header failed: %v", err)
	}
	return header, nil
}

func (getter *HeaderGetter) setHighestKnownBlock(hash []byte, height int) {
	getter.db.Set(kHighestKnownBlock, databaseBlockHeight{
		Hash:   hash,
		Height: height,
	})
}

type databaseBlockHeight struct {
	Hash   []byte
	Height int
}

func (getter *HeaderGetter) highestKnownBlock() ([]byte, int) {
	// TODO read from memory if no database is set.
	last := databaseBlockHeight{}
	err := getter.db.Get(kHighestKnownBlock, &last)
	if err != nil {
		log.Printf("Couldn't retrieve highest known block: %v", err)
		return make([]byte, 32), 0
	}
	return last.Hash, last.Height
}

func (getter *HeaderGetter) formGetHeaderMessage() network.Message {
	hash, height := getter.highestKnownBlock()
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
			header, err := getter.loadHeader(loc)
			if err != nil {
				log.Printf("Failed to get recent header, %d steps back: %v",
					i, err)
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
	log.Printf("Getting more headers, starting from %x at height %d.\n",
		utils.ReverseBytes(hash), height)
	return network.Message{
		Type: "getheaders",
		Data: msgBytes.Bytes(),
	}
}

func (getter *HeaderGetter) requestMoreHeaders() bool {
	// Wait for connection.
	select {
	case <-getter.inv.Connected():
		// do nothing.
	case <-getter.closeCh:
		return false
	}

	msg := getter.formGetHeaderMessage()
	endpoint := getter.inv.Send(msg)
	if endpoint == "" {
		log.Printf("No endpoint connected; wait for timeout and retry.")
	}

	var incomplete, received bool
	// TODO Increase timeout on large requests.
	timer := time.NewTimer(45 * time.Second)
	for !received {
		select {
		case m := <-getter.input:
			if m.Endpoint == endpoint {
				incomplete = getter.handleHeaders(m)
				received = true
			} else {
				log.Printf("Received unexpected message from %q "+
					"while waiting for message from %q.",
					m.Endpoint, endpoint)
			}
		case <-timer.C:
			if endpoint != "" {
				getter.inv.reportMisbehaviour(endpoint, 5,
					"getheaders request timed out.")
			}
			return true
		case <-getter.closeCh:
			timer.Stop()
			return false
		}
	}
	return incomplete
}

func (getter *HeaderGetter) getBlockHeight(hash []byte) (int, error) {
	prev, err := getter.loadHeader(hash)
	if err != nil {
		block0, _ := hex.DecodeString(
			"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
		if bytes.Equal(hash, utils.ReverseBytes(block0)) {
			return 0, nil
		}
		return -1, fmt.Errorf("Couldn't find prev block.")
	}
	return int(prev.Height), nil
}

func (getter *HeaderGetter) handleHeaders(m network.Message) bool {
	_, oldHeight := getter.highestKnownBlock()
	headers, err := messages.ParseHeaders(m.Data)
	if err != nil {
		log.Printf("Failed to parse headers: %v", err)
		return true
	}
	log.Printf("Received %d headers from %s.\n",
		len(headers), m.Endpoint)
	var hash []byte
	var height int
	var incomplete bool
	var vector messages.InventoryVector
	for _, h := range headers {
		prevHeight, err := getter.getBlockHeight(h.PrevBlock)
		if err != nil {
			log.Printf("Received bad header %x from %s.",
				utils.ReverseBytes(h.Hash()), m.Endpoint)
			// TODO handle this
			getter.inv.reportMisbehaviour(m.Endpoint, 20,
				"Sent bad block header.")
			incomplete = true
			break
		}
		height = prevHeight + 1
		h.Height = height
		hash = h.Hash()
		getter.db.Set(hash, h)

		// Request merkleblocks for headers.
		vector = append(vector, &messages.Inventory{
			Type: messages.TypeMsgFilteredBlock,
			Hash: hash,
		})
	}
	if len(hash) != 0 && height > oldHeight {
		getter.setHighestKnownBlock(hash, height)
		log.Printf("Last header updated to %x (internal byte order), height is %d.",
			utils.ReverseBytes(hash), height)
		if height < oldHeight+len(vector) {
			// TODO not all blocks are new, consider changing endpoint.
		}
	} else {
		// TODO If we haven't caught up yet, this means the endpoint is
		// misbehaving.
	}
	if len(headers) >= 2000 {
		incomplete = true
	} else {
		// TODO question if endpoint is good.
	}
	err = getter.inv.SendGetData(vector, m.Endpoint)
	if err != nil {
		return true
	}
	return incomplete
}
