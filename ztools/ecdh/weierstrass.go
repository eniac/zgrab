// Parameters for the weierstrass elliptic curves
// http://www.secg.org/SEC2-Ver-1.0.pdf
package ecdh

import (
	"crypto/elliptic"
	"github.com/keybase/go-crypto/brainpool"
	"io"
	"math/big"
	"sync"
)

type weierstrass struct {
	Curve
	curve elliptic.Curve
}

func NewWeierstrass(curve elliptic.Curve) Curve {
	return &weierstrass{
		curve: curve,
	}
}

func (e *weierstrass) GenerateKey(rand io.Reader) (*ECDHPrivateKey, *ECDHPublicKey, error) {
	var d []byte
	var x, y *big.Int
	var err error

	d, x, y, err = elliptic.GenerateKey(e.curve, rand)
	if err != nil {
		return nil, nil, err
	}

	priv := &ECDHPrivateKey{
		D: d,
	}

	pub := &ECDHPublicKey{
		X: x,
		Y: y,
	}

	return priv, pub, nil
}

func (e *weierstrass) Marshal(pub *ECDHPublicKey, compress bool) []byte {
    if compress {
        byteLen := (e.curve.Params().BitSize + 7) >> 3

        ret := make([]byte, 1+byteLen)
        ret[0] = byte(2 + pub.Y.Bit(e.curve.Params().BitSize)) // compressed point

        xBytes := pub.X.Bytes()
        copy(ret[1+byteLen-len(xBytes):], xBytes)
        return ret
    } else {
        return elliptic.Marshal(e.curve, pub.X, pub.Y)
    }
}

func (e *weierstrass) Unmarshal(data []byte) (*ECDHPublicKey, bool) {
	var key *ECDHPublicKey
	var x, y *big.Int
	// TODO: handle compressed points

	x, y = elliptic.Unmarshal(e.curve, data)
	if x == nil || y == nil {
		return key, false
	}
	key = &ECDHPublicKey{
		X: x,
		Y: y,
	}
	return key, true
}

func (e *weierstrass) GenerateSharedSecret(privKey *ECDHPrivateKey, pubKey *ECDHPublicKey) ([]byte, error) {
	x, _ := e.curve.ScalarMult(pubKey.X, pubKey.Y, privKey.D)
	return x.Bytes(), nil
}

var (
	once                                                   sync.Once
	p160k1, p160r1, p160r2, p192k1, p192r1, p224k1, p256k1 *elliptic.CurveParams
)

func initAll() {
	initP160k1()
	initP160r1()
	initP160r2()
	initP192k1()
	initP192r1()
	initP224k1()
	initP256k1()
}

func initP160k1() {
	p160k1 = new(elliptic.CurveParams)
	p160k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", 16)
	p160k1.N, _ = new(big.Int).SetString("0100000000000000000001B8FA16DFAB9ACA16B6B3", 16)
	p160k1.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000007", 16)
	p160k1.Gx, _ = new(big.Int).SetString("3B4C382CE37AA192A4019E763036F4F5DD4D7EBB", 16)
	p160k1.Gy, _ = new(big.Int).SetString("938CF935318FDCED6BC28286531733C3F03C4FEE", 16)
	p160k1.BitSize = 160
}

func initP160r1() {
	p160r1 = new(elliptic.CurveParams)
	p160r1.P, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffff7fffffff", 16)
	p160r1.N, _ = new(big.Int).SetString("0100000000000000000001f4c8f927aed3ca752257", 16)
	p160r1.B, _ = new(big.Int).SetString("1c97befc54bd7a8b65acf89f81d4d4adc565fa45", 16)
	p160r1.Gx, _ = new(big.Int).SetString("4a96b5688ef573284664698968c38bb913cbfc82", 16)
	p160r1.Gy, _ = new(big.Int).SetString("23a628553168947d59dcc912042351377ac5fb32", 16)
	p160r1.BitSize = 160
}

func initP160r2() {
	p160r2 = new(elliptic.CurveParams)
	p160r2.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", 16)
	p160r2.N, _ = new(big.Int).SetString("0100000000000000000000351EE786A818F3A1A16B", 16)
	p160r2.B, _ = new(big.Int).SetString("B4E134D3FB59EB8BAB57274904664D5AF50388BA", 16)
	p160r2.Gx, _ = new(big.Int).SetString("52DCB034293A117E1F4FF11B30F7199D3144CE6D", 16)
	p160r2.Gy, _ = new(big.Int).SetString("FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E", 16)
	p160r2.BitSize = 160
}

func initP192k1() {
	p192k1 = new(elliptic.CurveParams)
	p192k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", 16)
	p192k1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", 16)
	p192k1.B, _ = new(big.Int).SetString("000000000000000000000000000000000000000000000003", 16)
	p192k1.Gx, _ = new(big.Int).SetString("DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", 16)
	p192k1.Gy, _ = new(big.Int).SetString("9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", 16)
	p192k1.BitSize = 192
}

func initP192r1() {
	p192r1 = new(elliptic.CurveParams)
	p192r1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16)
	p192r1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 16)
	p192r1.B, _ = new(big.Int).SetString("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", 16)
	p192r1.Gx, _ = new(big.Int).SetString("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16)
	p192r1.Gy, _ = new(big.Int).SetString("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16)
	p192r1.BitSize = 192
}

func initP224k1() {
	p224k1 = new(elliptic.CurveParams)
	p224k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D", 16)
	p224k1.N, _ = new(big.Int).SetString("010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7", 16)
	p224k1.B, _ = new(big.Int).SetString("00000000000000000000000000000000000000000000000000000005", 16)
	p224k1.Gx, _ = new(big.Int).SetString("A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C", 16)
	p224k1.Gy, _ = new(big.Int).SetString("7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5", 16)
	p224k1.BitSize = 224
}

func initP256k1() {
	p256k1 = new(elliptic.CurveParams)
	p256k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	p256k1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	p256k1.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	p256k1.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	p256k1.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	p256k1.BitSize = 256
}

func P160k1() Curve {
	once.Do(initAll)
	return NewWeierstrass(p160k1)
}

func P160r1() Curve {
	once.Do(initAll)
	return NewWeierstrass(p160r1)
}

func P160r2() Curve {
	once.Do(initAll)
	return NewWeierstrass(p160r2)
}

func P192k1() Curve {
	once.Do(initAll)
	return NewWeierstrass(p192k1)
}

func P192r1() Curve {
	once.Do(initAll)
	return NewWeierstrass(p192r1)
}

func P224k1() Curve {
	once.Do(initAll)
	return NewWeierstrass(p224k1)
}

func P224r1() Curve {
	return NewWeierstrass(elliptic.P224())
}

func P256k1() Curve {
	once.Do(initAll)
	return NewWeierstrass(p256k1)
}

func P256r1() Curve {
	return NewWeierstrass(elliptic.P256())
}

func P384r1() Curve {
	return NewWeierstrass(elliptic.P384())
}

func P521r1() Curve {
	return NewWeierstrass(elliptic.P521())
}

func BrainpoolP256r1() Curve {
	return NewWeierstrass(brainpool.P256r1())
}

func BrainpoolP384r1() Curve {
	return NewWeierstrass(brainpool.P384r1())
}

func BrainpoolP512r1() Curve {
	return NewWeierstrass(brainpool.P512r1())
}

func BrainpoolP256t1() Curve {
	return NewWeierstrass(brainpool.P256t1())
}

func BrainpoolP384t1() Curve {
	return NewWeierstrass(brainpool.P384t1())
}

func BrainpoolP512t1() Curve {
	return NewWeierstrass(brainpool.P512t1())
}
