package rand

import (
	crypto "crypto/rand"
	"encoding/hex"
	"math/rand"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func String(length int) string {
	return StringWithCharset(length, charset)
}

func Hex_128() string {
	return hex.EncodeToString(Bytes(16))
}

func Int(max int) int {
	return seededRand.Intn(max)
}

func Bytes(n int) []byte {
	b := make([]byte, n)

	_, err := crypto.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}
