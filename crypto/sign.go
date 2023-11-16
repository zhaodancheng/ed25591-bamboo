package crypto

import (
	"crypto/ed25519"

	"github.com/gitferry/bamboo/config"
	"github.com/gitferry/bamboo/identity"
	"github.com/gitferry/bamboo/log"
)

// SigningAlgorithm is an identifier for a signing algorithm and curve.

//type SigningAlgorithm string

// String returns the string representation of this signing algorithm.
// func (f SigningAlgorithm) String() string {
//	return [...]string{"UNKNOWN", "BLS_BLS12381", "ECDSA_P256", "ECDSA_SECp256k1"}[f]
//}

const (
	// Supported signing algorithms
	//UnknownSigningAlgorithm SigningAlgorithm = iota
	BLS_BLS12381    = "BLS_BLS12381"
	ECDSA_P256      = "ECDSA_P256"
	ECDSA_SECp256k1 = "ECDSA_SECp256k1"
	SCHNORR_ED25519 = "SCHNORR_ED25519"
)

var keys []PrivateKey
var pubKeys []PublicKey

// PrivateKey is an unspecified signature scheme private key
type PrivateKey interface {
	// Algorithm returns the signing algorithm related to the private key.
	Algorithm() string
	// KeySize return the key size in bytes.
	// KeySize() int
	// Sign generates a signature using the provided hasher.
	Sign([]byte, Hasher) (Signature, error)
	// PublicKey returns the public key.
	PublicKey() PublicKey
	// Encode returns a bytes representation of the private key
	//Encode() ([]byte, error)
}

// PublicKey is an unspecified signature scheme public key.
type PublicKey interface {
	// Algorithm returns the signing algorithm related to the public key.
	Algorithm() string
	// KeySize return the key size in bytes.
	//KeySize() int
	// Verify verifies a signature of an input message using the provided hasher.
	Verify(Signature, Hash) (bool, error)
	// Encode returns a bytes representation of the public key.
	//Encode() ([]byte, error)
}

type StaticRand struct {
	identity.NodeID
}

func (sr *StaticRand) Read(x []byte) (int, error) {
	return sr.Node(), nil
}

// SetKeys 函数用于初始化私钥和公钥。
func SetKeys() error {
	keys = make([]PrivateKey, config.GetConfig().N())
	pubKeys = make([]PublicKey, config.GetConfig().N())
	var err error
	for i := 0; i < config.GetConfig().N(); i++ {
		keys[i], err = GenerateKey(config.GetConfig().GetSignatureScheme(), identity.NewNodeID(i+1))
		if err != nil {
			log.Fatal("不能生成公钥", err)
			return err
		}
		pubKeys[i] = keys[i].PublicKey()
	}
	return nil
}

// GenerateKey 函数用于生成指定签名算法的私钥。它接受签名算法标识和节点标识作为参数，然后根据算法生成相应的私钥。
func GenerateKey(signer string, id identity.NodeID) (PrivateKey, error) {
	if signer == SCHNORR_ED25519 {
		// 使用 ed25519 签名算法
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			log.Fatal("GenerateKey错误", err)
			return nil, err
		}
		privKey := &ed25519_PrivateKey{SignAlg: signer, PrivateKey: priv}
		return privKey, nil
	} else if signer == ECDSA_SECp256k1 {
		return nil, nil
	} else if signer == BLS_BLS12381 {
		return nil, nil
	} else {
		// 使用 ed25519 签名算法
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			log.Fatal("GenerateKey错误", err)
			return nil, err
		}
		privKey := &ed25519_PrivateKey{SignAlg: signer, PrivateKey: priv}
		return privKey, nil
		// log.Fatal("没有返回值", signer)
		// return nil, errors.New("Invalid signature scheme!")
	}
}

// Use the following functions for signing and verification.
// PrivSign 函数：PrivSign 函数用于使用私钥对数据进行签名。
// 它接受数据、节点标识和哈希器作为参数，并返回数字签名。
func PrivSign(data []byte, nodeID identity.NodeID, hasher Hasher) (Signature, error) {
	return keys[nodeID.Node()-1].Sign(data, hasher)
}

// PubVerify 函数：PubVerify 函数用于验证数字签名。它接受签名、数据和节点标识作为参数，并返回签名是否有效。
// 这个函数允许使用节点的公钥来验证签名。
func PubVerify(sig Signature, data []byte, nodeID identity.NodeID) (bool, error) {
	return pubKeys[nodeID.Node()-1].Verify(sig, data)
}

// 这个函数名为 VerifyQuorumSignature，用于验证多个节点的签名
func VerifyQuorumSignature(aggregatedSigs AggSig, blockID Identifier, aggSigners []identity.NodeID) (bool, error) {
	var sigIsCorrect bool
	var errAgg error
	for i, signer := range aggSigners {
		sigIsCorrect, errAgg = PubVerify(aggregatedSigs[i], IDToByte(blockID), signer)
		if errAgg != nil {
			return false, errAgg
		}
		if sigIsCorrect == false {
			return false, nil
		}
	}
	return true, nil
}
