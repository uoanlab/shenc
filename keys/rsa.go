package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
)

type PublicKeyRSA struct {
	key *rsa.PublicKey
}

type PrivateKeyRSA struct {
	key *rsa.PrivateKey
}

func (p PublicKeyRSA) Encrypt(data []byte) ([]byte, error) {
	encdata, err := rsa.EncryptPKCS1v15(rand.Reader, p.key, data)
	if err != nil {
		return nil, err
	}
	return encdata, nil
}

func (p PublicKeyRSA) Verify(hash []byte, sig []byte) error {
	return rsa.VerifyPKCS1v15(p.key, crypto.SHA256, hash, sig)
}

func (p PublicKeyRSA) Marshal() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(p.key)
}

func (p PublicKeyRSA) Fingerprint() []byte {
	pub, err := p.Marshal()
	if err != nil {
		return nil
	}
	hash := sha256.Sum256(pub)
	return hash[:]
}

func (p PrivateKeyRSA) Decrypt(data []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, p.key, data)
}

func (p PrivateKeyRSA) Sign(hashed []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, hashed)
}

func (p PrivateKeyRSA) Public() PublicKey {
	return PublicKeyRSA{key: &p.key.PublicKey}
}

func (p PrivateKeyRSA) Marshal() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(p.key)
}
