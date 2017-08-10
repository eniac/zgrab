// Interface for Elliptic Curve Diffie Hellman curves.
// Modification of https://github.com/wsddn/go-ecdh/blob/master/elliptic.go
package ecdh

import (
	"io"
	"math/big"
)

type ECDHPublicKey struct {
	X, Y *big.Int
}

type ECDHPrivateKey struct {
	D []byte
}

type Curve interface {
	GenerateKey(io.Reader) (*ECDHPrivateKey, *ECDHPublicKey, error)
	Marshal(*ECDHPublicKey) []byte
	Unmarshal([]byte) (*ECDHPublicKey, bool)
	GenerateSharedSecret(*ECDHPrivateKey, *ECDHPublicKey) ([]byte, error)
}
