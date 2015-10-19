package inventory

import (
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/aarbt/bitcoin-wallet/database"
	"github.com/aarbt/bitcoin-wallet/messages"
	"github.com/aarbt/bitcoin-wallet/utils"
)

func LoadTransactions(db *database.DB) map[string]*Data {
	inv := make(map[string]*Data)
	list := db.LoadAllTransactions()
	for i, t := range list {
		tx, err := messages.ParseTransaction(t.Data)
		if err != nil {
			log.Printf("Error loading transaction #%d: %v", i, err)
			continue
		}
		data := NewData(tx.Hash())
		if t.Block.Height > 0 {
			data.Block = t.Block
		}
		data.TX = tx
		inv[string(tx.Hash())] = data
		log.Printf("Loaded transaction: %v", data)
	}
	return inv
}

type Data struct {
	Hash      []byte
	peers     map[string]time.Time
	Block     *database.Block // Included in block
	timestamp time.Time       // First seen
	TX        *messages.Transaction
}

func NewData(hash []byte) *Data {
	return &Data{
		Hash:      hash,
		peers:     make(map[string]time.Time),
		timestamp: time.Now(),
	}
}

func (d *Data) AddPeer(key string) {
	d.peers[key] = time.Now()
}

func (d *Data) Peers() []string {
	list := make([]string, 0, len(d.peers))
	for k, _ := range d.peers {
		list = append(list, k)
	}
	sort.Strings(list)
	return list
}

func (d *Data) Timestamp() time.Time {
	timestamp := d.timestamp
	if d.Block != nil && d.Block.Timestamp.Before(timestamp) {
		timestamp = d.Block.Timestamp
	}
	return timestamp
}

func (d *Data) String() string {
	str := d.Timestamp().String()

	str += fmt.Sprintf(" TX: %x", utils.ReverseBytes(d.Hash))
	if d.TX == nil {
		str += " HEAD ONLY"
	}
	if d.Block != nil {
		str += fmt.Sprintf(" included in block at %s", d.Block.Timestamp)
	} else {
		str += fmt.Sprintf(" Unconfirmed (received from %d peers)",
			len(d.peers))
	}
	return str
}

type DataListByTime []*Data

func (slice DataListByTime) Len() int {
	return len(slice)
}

func (slice DataListByTime) Less(i, j int) bool {
	return slice[i].Timestamp().Before(slice[j].Timestamp())
}

func (slice DataListByTime) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}
