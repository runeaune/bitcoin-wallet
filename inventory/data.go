package inventory

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/aarbt/bitcoin-wallet/messages"
	"github.com/aarbt/bitcoin-wallet/utils"
)

type TxLoader interface {
	LoadAllTransactions() []*TxVersion
}

func (inv *Inventory) loadTransactions(db TxLoader) {
	list := db.LoadAllTransactions()
	for _, t := range list {
		inv.txHashes[string(t.Hash)] = t
		id := t.Id()
		if id != nil {
			tx, found := inv.transactions[string(id)]
			if !found {
				tx = &Transaction{
					id:        id,
					timestamp: time.Now(), // TODO fix this.
					versions:  make(map[string]*messages.Transaction),
				}
				inv.transactions[string(id)] = tx
			}
			tx.versions[string(t.Hash)] = t.tx
			if t.Block != nil {
				tx.block = t.Block
			}
		}
	}
}

type Block struct {
	Hash      []byte    // 32 bytes
	Timestamp time.Time // 4 bytes
	Height    int32     // 4 bytes
}

type TxVersion struct {
	Hash  []byte `json:"hash,omitempty"`
	Block *Block `json:"block,omitempty"`

	// Another duplicate of this version has been confirmed.
	InvalidatedBy []byte `json:"invalidated_by,omitempty"`

	// Only used for storing and loading tx.
	Data []byte `json:"data,omitempty"`
	tx   *messages.Transaction
}

func (t TxVersion) String() string {
	str := fmt.Sprintf("Transaction %x", utils.ReverseBytes(t.Hash))
	if t.tx != nil {
		str += fmt.Sprintf(" fingerprint %x", t.Id())
	}
	if t.Block != nil {
		str += fmt.Sprintf(" in block %x (height %d)", t.Block.Hash, t.Block.Height)
	}
	return str
}

func (t *TxVersion) Id() []byte {
	if t.tx != nil {
		return t.tx.Fingerprint()
	} else {
		return nil
	}
}

func (t *TxVersion) DeserializeTransaction() error {
	if len(t.Data) > 0 && t.tx == nil {
		var err error
		t.tx, err = messages.ParseTransaction(t.Data)
		if err != nil {
			return fmt.Errorf("Failed to parse transaction: %v", err)
		}
	}
	return nil
}

func (t *TxVersion) SerializeTransaction() {
	if t.tx != nil && t.Data == nil {
		t.Data = t.tx.Data()
	}
}

type Transaction struct {
	id        []byte
	timestamp time.Time
	versions  map[string]*messages.Transaction
	block     *Block // Included in block
}

type TxOutput struct {
	output  *messages.TxOutput
	index   uint32
	tx      *TxVersion
	spentBy *messages.Transaction

	// Unique ID of transaction; may have mulitple versions.
	id []byte
}

func Fingerprint(hash []byte, i uint32) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, i)
	return append(hash, b.Bytes()...)
}

// Fingerprint returns a unique identifier of the output.
func (out *TxOutput) Fingerprint() []byte {
	return Fingerprint(out.tx.Hash, out.index)
}

// TxHash returns the hash of the transaction the output belongs to.
func (out *TxOutput) TxHash() []byte {
	return out.tx.Hash
}

/*
type Data struct {
	Hashes    [][]byte
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
*/
