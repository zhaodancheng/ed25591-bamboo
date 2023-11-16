package crypto

import (
	"github.com/gitferry/bamboo/config"
	"github.com/gitferry/bamboo/types/encoding"
)

type Identifier [32]byte

// MakeID creates an ID from the hash of encoded data.
func MakeID(body interface{}) Identifier {
	data := encoding.DefaultEncoder.MustEncode(body)
	hasher := NewSHA3_256()
	if config.GetConfig().GetSignatureScheme() == ED25519 {
		hasher = NewED25519() // 如果使用 Ed25519 签名算法，则使用 Ed25519 哈希算法
	}
	hash := hasher.ComputeHash(data)
	return HashToID(hash)
}

func HashToID(hash []byte) Identifier {
	var id Identifier
	copy(id[:], hash)
	return id
}

func IDToByte(id Identifier) []byte {
	return id[:]
}
