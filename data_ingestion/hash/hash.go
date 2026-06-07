package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
)

func Document(body string) ([]byte, string) {
	h := sha256.New()
	io.Copy(h, strings.NewReader(body))
	raw := h.Sum(nil)
	return raw, hex.EncodeToString(raw)
}
