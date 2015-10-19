package database

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/golang/leveldb"
)

const kTxStoragePrefix = "TX: "

// TODO Compress storage format. Speed up by using batching.

type DB struct {
	db *leveldb.DB

	// Number of transactions stored in the database.
	transactionCount int
}

func Open() *DB {
	db, err := leveldb.Open("db", nil)
	if err != nil {
		panic(fmt.Sprintf("Couldn't open database: %v", err))
	}
	return &DB{
		db: db,
	}
}

func (db *DB) Close() {
	db.db.Close()
}

func (db *DB) Set(key []byte, data interface{}) {
	j, _ := json.Marshal(data)
	err := db.db.Set(key, j, nil)
	if err != nil {
		log.Printf("Failed to insert header %x into database: %v",
			key, err)
	}
}

func (db *DB) Get(key []byte, data interface{}) error {
	j, err := db.db.Get(key, nil)
	if err != nil || len(j) == 0 {
		return fmt.Errorf("Data %x not found: %v", key, err)
	}

	err = json.Unmarshal(j, data)
	if err != nil {
		return fmt.Errorf("Failed to parse extended header %x in db: %v",
			key, err)
	}
	return nil
}

// LoadAllTransactions loads data with keys on the format "tx:HHHH", where HHHH
// is a hexadecimal counter, until no data is found for a value of the counter.
// This is considered to be all stored transactions. It does not check for
// duplicates. If duplicates are found, the later one should be used.
// TODO Find a better way to store transactions.
func (db *DB) LoadAllTransactions() []*Transaction {
	var list []*Transaction
	db.transactionCount = 0
	for {
		key := fmt.Sprintf(kTxStoragePrefix+"%x", db.transactionCount)
		data, err := db.db.Get([]byte(key), nil)
		if err != nil || len(data) == 0 {
			log.Printf("Transaction #%d not in storage: %v",
				db.transactionCount, err)
			break
		}
		db.transactionCount++
		tx := ParseTransaction(data)
		if tx != nil {
			list = append(list, tx)
		}
	}
	return list
}

// Only call after LoadAllTransactions has completed. Due to how difficult it
// is to update transactions after the fact, duplicates storage of the same
// transaction is fine as long as they are incrementally more complete/correct.
func (db *DB) StoreNewTransaction(tx *Transaction) {
	key := fmt.Sprintf(kTxStoragePrefix+"%x", db.transactionCount)
	err := db.db.Set([]byte(key), tx.Serialize(), nil)
	if err != nil {
		log.Printf("Failed to insert transaction %x into database: %v",
			key, err)
	}
	db.transactionCount++
	log.Printf("Stored transaction, total is %d.", db.transactionCount)
}

type Block struct {
	Hash      []byte    // 32 bytes
	Timestamp time.Time // 4 bytes
	Height    int32     // 4 bytes
}

func (b *Block) Serialize() []byte {
	var ser bytes.Buffer
	ser.Write(b.Hash)
	timestamp := uint32(b.Timestamp.Unix())
	binary.Write(&ser, binary.LittleEndian, timestamp)
	binary.Write(&ser, binary.LittleEndian, b.Height)
	return ser.Bytes()
}

func ParseBlock(data []byte) *Block {
	b := Block{Hash: data[0:32]}
	r := bytes.NewBuffer(data[32:])
	var timestamp uint32
	binary.Read(r, binary.LittleEndian, &timestamp)
	b.Timestamp = time.Unix(int64(timestamp), 0)
	binary.Read(r, binary.LittleEndian, &b.Height)
	return &b
}

type Transaction struct {
	Block *Block // 40 bytes
	Data  []byte // Variable
}

func (t *Transaction) Serialize() []byte {
	var ser bytes.Buffer
	if t.Block != nil {
		ser.Write(t.Block.Serialize())
	} else {
		nils := make([]byte, 40)
		ser.Write(nils)
	}
	ser.Write(t.Data)
	return ser.Bytes()
}

func ParseTransaction(data []byte) *Transaction {
	if len(data) <= 50 {
		// Too short, don't even try.
		return nil
	}
	t := Transaction{
		Block: ParseBlock(data[0:40]),
		Data:  data[40:],
	}
	return &t
}
