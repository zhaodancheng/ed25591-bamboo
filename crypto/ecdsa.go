package crypto

import (
	"crypto/ed25519"
)

type ed25519_PrivateKey struct {
	SignAlg    string
	PrivateKey ed25519.PrivateKey
}

type ed25519_PublicKey struct {
	SignAlg   string
	PublicKey ed25519.PublicKey
}

// 用于获取对应私钥的公钥
func (priv *ed25519_PrivateKey) PublicKey() PublicKey {
	pub := &ed25519_PublicKey{SignAlg: ED25519, PublicKey: priv.PrivateKey.Public().(ed25519.PublicKey)}
	return pub
}

// ed25519_PublicKey 结构体定义了一个方法，用于返回对应的签名算法。
func (priv *ed25519_PrivateKey) Algorithm() string {
	return priv.SignAlg
}

// This function is commented for now.
// func (priv *ecdsa_p256_PrivateKey) KeySize() int {
//	return len([]byte(*priv))
// }

// ecdsa.Sign returns two *big.Int variables. In order to save it in the Signature type,
// I first turn them into strings, and then I turn the strings to byte arrays.
// I have implemented a Signature to ecdsa signature parser (toECDSA in signature.go) in oder to
// cast the byte array Signature into the original signature of the ECDSA signing method.
// ecdsa.Sign返回两个*big.Int变量。为了将其保存在Signature类型中，
// 首先我将它们转换为字符串，然后将字符串转换为字节数组。
// 我还实现了一个Signature到ECDSA签名解析器（在signature.go中的toECDSA），
// 以便将字节数组类型的Signature转换为ECDSA签名方法的原始签名。
// func (priv *ecdsa_p256_PrivateKey) Sign(msg []byte, hasher Hasher) (Signature, error) {
func (priv *ed25519_PrivateKey) Sign(msg []byte, hasher Hasher) (Signature, error) {
	// 使用 Ed25519 签名算法进行签名
	sig := ed25519.Sign(priv.PrivateKey, msg)
	return Signature(sig), nil
}

func (pub *ed25519_PublicKey) Algorithm() string {
	return pub.SignAlg
}

func (pub *ed25519_PublicKey) Verify(sig Signature, hash Hash) (bool, error) {
	// 使用 Ed25519 签名算法进行验证
	return ed25519.Verify(pub.PublicKey, hash, []byte(sig)), nil
}
