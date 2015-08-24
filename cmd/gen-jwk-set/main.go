package main

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/square/go-jose"
)

func main() {
	var flagAlg = flag.String("alg", "", "specify an algorithm")
	flag.Parse()

	if *flagAlg == "" {
		flag.Usage()
		return
	}

	rawPublicKey, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal("unable to read a public key from stdin:", err)
	}

	publicKey, err := jose.LoadPublicKey(rawPublicKey)
	if err != nil {
		log.Fatal("unable to load a public key:", err)
	}

	hasher := crypto.SHA256.New()
	fmt.Fprint(hasher, rawPublicKey)
	hashed := hex.EncodeToString(hasher.Sum(nil))

	// TODO(nabeken): be able to specify multiple keys
	jwks := struct {
		Keys []*jose.JsonWebKey `json:"keys"`
	}{
		Keys: []*jose.JsonWebKey{
			&jose.JsonWebKey{
				Key:       publicKey,
				KeyID:     hashed,
				Algorithm: *flagAlg,
			},
		},
	}

	json.NewEncoder(os.Stdout).Encode(jwks)
}
