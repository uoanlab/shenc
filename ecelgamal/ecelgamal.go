package ecelgamal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
)

var (
	ErrFailToConvertBytesToPoint = errors.New("fail to convert byte array to point")
	ErrMessageTooLong            = errors.New("message too long for EC public key size")
	ErrInvalidCipherText         = errors.New("invalid ciphertext")
)

// CryptoData is an EC ElGamal crypto data
type CipherText struct {
	C1x, C1y, C2x, C2y *big.Int
}

// GenerateKey generates a private key.
func GenerateKey(c elliptic.Curve, rand io.Reader) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(c, rand)
}

// Calculate legendre symbol
func Legendre(x, p *big.Int) int {
	e := big.NewInt(0).Sub(p, big.NewInt(1)) // p-1
	e.Div(e, big.NewInt(2))                  // (p-1)/2
	l := big.NewInt(0).Exp(x, e, p)          // l = x^((p-1)/2) mod p

	if l.Sign() == 0 {
		// l==0
		return 0
	} else if l.Cmp(big.NewInt(1)) == 0 {
		// Quadratic residue
		return 1
	}
	return -1
}

// Convert byte array to curve point
func ByteToPoint(c elliptic.Curve, m []byte) (*big.Int, *big.Int, error) {

	if len(m) >= c.Params().BitSize/8 {
		return nil, nil, ErrMessageTooLong
	}

	m1000 := big.NewInt(0).SetBytes(m) // m
	m1000.Mul(m1000, big.NewInt(1000)) // 1000m

	for i := 0; i < 1000; i++ {
		x := big.NewInt(int64(i))
		x.Add(x, m1000) // 1000m + i

		x3 := big.NewInt(0).Mul(x, x)
		x3.Mul(x3, x) // x^3

		ax := big.NewInt(0).Mul(x, big.NewInt(3)) // ax (a = 3)

		z := big.NewInt(0).Sub(x3, ax) // x^3 - ax
		z.Add(z, c.Params().B)         // x^3 - ax + b

		if Legendre(z, c.Params().P) == 1 {
			y := big.NewInt(0)
			y.ModSqrt(z, c.Params().P)
			if c.IsOnCurve(x, y) {
				return x, y, nil
			}
		}
	}

	// It's so unlucky that the point is not found corresponding to the message
	return nil, nil, ErrFailToConvertBytesToPoint
}

func Encrypt(pubkey *ecdsa.PublicKey, m []byte) (CipherText, error) {
	c := pubkey.Curve
	// Generate a random number k
	k := make([]byte, (c.Params().BitSize+7)/8)
	for {
		_, err := rand.Read(k)
		if err != nil {
			return CipherText{}, err
		}
		if k[0] != 0 {
			break
		}
	}
	// trim excess bits
	// k should be big endian
	if c.Params().BitSize%8 > 0 {
		k[0] &= 0xFF >> (8 - c.Params().BitSize%8)
	}

	// convert m to curve point
	mx, my, err := ByteToPoint(c, m)
	if err != nil {
		return CipherText{}, err
	}

	// Calculate kG
	c1x, c1y := c.ScalarBaseMult(k)
	// Calculate kP + M
	c2x, c2y := c.ScalarMult(pubkey.X, pubkey.Y, k)
	c2x, c2y = c.Add(c2x, c2y, mx, my)
	return CipherText{c1x, c1y, c2x, c2y}, nil
}

func Decrypt(privkey *ecdsa.PrivateKey, ct CipherText) ([]byte, error) {
	c := privkey.Curve

	if !c.IsOnCurve(ct.C1x, ct.C1y) || !c.IsOnCurve(ct.C2x, ct.C2y) {
		return nil, ErrInvalidCipherText
	}

	kac1x, kac1y := c.ScalarMult(ct.C1x, ct.C1y, privkey.D.Bytes()) // xC1
	kac1ym := big.NewInt(0).Mul(kac1y, big.NewInt(-1))              // -xC1
	kac1ym.Mod(kac1ym, c.Params().P)                                // -xC1 (mod p)
	mx, _ := c.Add(ct.C2x, ct.C2y, kac1x, kac1ym)                   // C2 + (-xC1) = kP + M - xkG = k(xG) + M - xkG = M

	m := big.NewInt(0).Div(mx, big.NewInt(1000))
	return m.Bytes(), nil
}

func (ct CipherText) Marshal() []byte {
	ret := []byte{}

	c1x := ct.C1x.Bytes()
	c1xlen := make([]byte, 2)
	binary.LittleEndian.PutUint16(c1xlen, uint16(len(c1x)))
	ret = append(ret, c1xlen...)
	ret = append(ret, c1x...)

	c1y := ct.C1y.Bytes()
	c1ylen := make([]byte, 2)
	binary.LittleEndian.PutUint16(c1ylen, uint16(len(c1y)))
	ret = append(ret, c1ylen...)
	ret = append(ret, c1y...)

	c2x := ct.C2x.Bytes()
	c2xlen := make([]byte, 2)
	binary.LittleEndian.PutUint16(c2xlen, uint16(len(c2x)))
	ret = append(ret, c2xlen...)
	ret = append(ret, c2x...)

	c2y := ct.C2y.Bytes()
	c2ylen := make([]byte, 2)
	binary.LittleEndian.PutUint16(c2ylen, uint16(len(c2y)))
	ret = append(ret, c2ylen...)
	ret = append(ret, c2y...)

	return ret
}

func UnmarshalCipherText(dat []byte) (CipherText, error) {
	i := 0

	if len(dat)-i < 2 {
		return CipherText{}, ErrInvalidCipherText
	}
	c1xlen := binary.LittleEndian.Uint16(dat[i : i+2])
	i += 2
	if len(dat)-i < int(c1xlen) {
		return CipherText{}, ErrInvalidCipherText
	}
	c1x := dat[i : i+int(c1xlen)]
	i += int(c1xlen)

	if len(dat)-i < 2 {
		return CipherText{}, ErrInvalidCipherText
	}
	c1ylen := binary.LittleEndian.Uint16(dat[i : i+2])
	i += 2
	if len(dat)-i < int(c1ylen) {
		return CipherText{}, ErrInvalidCipherText
	}
	c1y := dat[i : i+int(c1ylen)]
	i += int(c1ylen)

	if len(dat)-i < 2 {
		return CipherText{}, ErrInvalidCipherText
	}
	c2xlen := binary.LittleEndian.Uint16(dat[i : i+2])
	i += 2
	if len(dat)-i < int(c2xlen) {
		return CipherText{}, ErrInvalidCipherText
	}
	c2x := dat[i : i+int(c2xlen)]
	i += int(c2xlen)

	if len(dat)-i < 2 {
		return CipherText{}, ErrInvalidCipherText
	}
	c2ylen := binary.LittleEndian.Uint16(dat[i : i+2])
	i += 2
	if len(dat)-i < int(c2ylen) {
		return CipherText{}, ErrInvalidCipherText
	}
	c2y := dat[i : i+int(c2ylen)]
	i += int(c2ylen)

	return CipherText{
		C1x: new(big.Int).SetBytes(c1x),
		C1y: new(big.Int).SetBytes(c1y),
		C2x: new(big.Int).SetBytes(c2x),
		C2y: new(big.Int).SetBytes(c2y),
	}, nil
}
