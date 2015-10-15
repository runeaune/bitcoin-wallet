package inventory

import (
	"encoding/hex"
	"log"
)

func (inv *Inventory) VerifySignature(hash []byte) bool {
	key := hex.EncodeToString(hash)
	tx, found := inv.data[key]
	if !found {
		log.Printf("Tx %x not found.", hash)
		return false
	}
	if tx.TX != nil {
		log.Printf("For signing 0: %x\n", tx.TX.SignSerialize(0, []byte{0xff, 0xaa, 0xaa, 0xff}, 1))
	}

	/*
		key, err := bitecdsa.GenerateKey(bitelliptic.S256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		data := []byte("fhsjkfhk")
		r, s, err := bitecdsa.Sign(rand.Reader, key, data)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(bitecdsa.Verify(&key.PublicKey, data, r, s))
	*/
	return true
}
