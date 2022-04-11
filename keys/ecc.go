package keys

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"

	"github.com/uoanlab/shenc/ecelgamal"
)

type PublicKeyECC struct {
	key *ecdsa.PublicKey
}
type PrivateKeyECC struct {
	key *ecdsa.PrivateKey
}

func (p PublicKeyECC) Encrypt(data []byte) ([]byte, error) {
	ct, err := ecelgamal.Encrypt(p.key, data)
	if err != nil {
		return nil, err
	}
	ret := ct.Marshal()
	return ret, nil
}

func (p PublicKeyECC) Verify(hash []byte, sig []byte) error {
	if !ecdsa.VerifyASN1(p.key, hash, sig) {
		return ErrInvalidSignature
	}
	return nil
}

func (p PublicKeyECC) Marshal() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(p.key)
}

func (p PublicKeyECC) Fingerprint() []byte {
	pub, err := p.Marshal()
	if err != nil {
		return nil
	}
	hash := sha256.Sum256(pub)
	return hash[:]
}

func (p PrivateKeyECC) Decrypt(data []byte) ([]byte, error) {
	ct, err := ecelgamal.UnmarshalCipherText(data)
	if err != nil {
		return nil, err
	}
	return ecelgamal.Decrypt(p.key, ct)
}

func (p PrivateKeyECC) Sign(hash []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, p.key, hash)
}

func (p PrivateKeyECC) Public() PublicKey {
	return PublicKeyECC{key: &p.key.PublicKey}
}

func (p PrivateKeyECC) Marshal() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(p.key)
}
