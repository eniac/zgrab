package ssh

import (
	"crypto/elliptic"
	"math/big"
)

type ECDHParams struct {
	SSHCurveID string         `json:"curve_id"`
	Curve      elliptic.Curve `json:"-"`
}

// This implementation does not work, since elliptic.Curve expects the 'a' parameter to be -3, which is not the case for Curve25519
func Curve25519() elliptic.Curve {
	c := &elliptic.CurveParams{Name: "Curve25519"}
	c.P, _ = new(big.Int).SetString("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 10)
	c.N, _ = new(big.Int).SetString("0x80000000000000000000000000000000a6f7cef517bce6b2c09318d2e7ae9f68", 10)
	c.B, _ = new(big.Int).SetString("0x7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864", 16)
	//c.A, _ = new(big.Int).SetString("0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144", 16)
	c.Gx, _ = new(big.Int).SetString("0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a", 16)
	c.Gy, _ = new(big.Int).SetString("0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9", 16)
	c.BitSize = 256
	return c
}
