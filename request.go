package jwt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

func StateToken() string {
	randBuf := make([]byte, 30)
	rand.Read(randBuf)
	hasher := sha256.New()
	hasher.Sum(randBuf)
	return hex.EncodeToString(hasher.Sum(nil))
}
