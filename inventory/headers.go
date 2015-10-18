package inventory

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/aarbt/bitcoin-network"
	"github.com/aarbt/bitcoin-wallet/database"
	"github.com/aarbt/bitcoin-wallet/messages"
	"github.com/aarbt/bitcoin-wallet/utils"
)

type HeaderGetter struct {
	inv    *Inventory
	input  chan network.Message
	output chan *messages.ExtendedHeader
	db     *database.DB

	closing bool
	closeCh chan struct{}
	doneCh  chan struct{}
}

func GetHeaders(inv *Inventory, db *database.DB) *HeaderGetter {
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
	getter.closing = true
	close(getter.closeCh)
	<-getter.doneCh
}

func (getter *HeaderGetter) Run() {
	go func() {
		for !getter.closing {
			incomplete := getter.requestMoreHeaders()
			if getter.closing {
				break
			}
			if !incomplete {
				time.Sleep(10 * time.Second)
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

func (getter *HeaderGetter) loadHeader(hash []byte) *messages.ExtendedHeader {
	header := &messages.ExtendedHeader{}
	err := getter.db.Get(hash, header)
	if err != nil {
		log.Printf("Getting header failed: %v", err)
		return nil
	}
	return header
}

func (getter *HeaderGetter) setHighestKnownBlock(hash []byte, height uint) {
	getter.db.Set(kHighestKnownBlock, databaseBlockHeight{
		Hash:   hash,
		Height: height,
	})
}

type databaseBlockHeight struct {
	Hash   []byte
	Height uint
}

func (getter *HeaderGetter) highestKnownBlock() ([]byte, uint) {
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
			header := getter.loadHeader(loc)
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

func (getter *HeaderGetter) setMessageHeight(m *messages.ExtendedHeader) (uint, error) {
	prev := getter.loadHeader(m.PrevBlock)
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
	var height uint
	var incomplete bool
	var vector messages.InventoryVector
	for _, h := range headers {
		height, err = getter.setMessageHeight(h)
		if err != nil {
			log.Printf("Received bad header %x from %s.",
				utils.ReverseBytes(h.Hash()), m.Endpoint)
			// TODO handle this
			getter.inv.reportMisbehaviour(m.Endpoint, 10,
				"Sent bad block header.")
			incomplete = true
			break
		}
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
		if height < oldHeight+uint(len(vector)) {
			// TODO not all blocks are new, consider changing endpoint.
		}
	} else {
		getter.inv.reportMisbehaviour(m.Endpoint, 10,
			"No new headers in received message.")
		incomplete = true
	}
	if len(headers) >= 2000 {
		incomplete = true
	} else {
		// TODO question if endpoint is good.
	}
	if len(vector) > 0 {
		data, err := messages.EncodeInventoryVector(vector)
		if err != nil {
			log.Printf("Failed to encode getdata vector: %v", err)
			return true
		}
		getter.inv.Send(network.Message{
			Type: "getdata",
			Data: data,
		})
	}
	return incomplete
}
