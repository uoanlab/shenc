package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

var ErrInvalidSignature = errors.New("invalid signature")

const (
	PEM_TYPE_PUBLIC_KEY  = "PUBLIC KEY"
	PEM_TYPE_PRIVATE_KEY = "PRIVATE KEY"
)

type PublicKey interface {
	Encrypt([]byte) ([]byte, error)
	Verify(hash []byte, sig []byte) error
	Marshal() ([]byte, error)
	Fingerprint() []byte
}
type PrivateKey interface {
	Decrypt([]byte) ([]byte, error)
	Sign([]byte) ([]byte, error)
	Public() PublicKey
	Marshal() ([]byte, error)
}

func marshalPEM(datatype string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: datatype, Bytes: data})
}

func unmarshalPEM(data []byte) (string, []byte) {
	p, _ := pem.Decode(data)
	if p == nil {
		return "", nil
	}
	return p.Type, p.Bytes
}

func UnmarshalPublicKey(data []byte) (PublicKey, error) {
	pubkey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}
	switch pubkey := pubkey.(type) {
	case *rsa.PublicKey:
		return PublicKeyRSA{key: pubkey}, nil
	case *ecdsa.PublicKey:
		return PublicKeyECC{key: pubkey}, nil
	default:
		return nil, ErrInvalidKey
	}
}
func UnmarshalPrivateKey(data []byte) (PrivateKey, error) {
	privkey, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, err
	}
	switch privkey := privkey.(type) {
	case *rsa.PrivateKey:
		return PrivateKeyRSA{key: privkey}, nil
	case *ecdsa.PrivateKey:
		return PrivateKeyECC{key: privkey}, nil
	default:
		return nil, ErrInvalidKey
	}
}

var ErrInvalidKey = errors.New("invalid key")

func LoadPublicKeyFromFile(name string) (PublicKey, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	dtype, data := unmarshalPEM(data)
	if dtype != PEM_TYPE_PUBLIC_KEY {
		return nil, ErrInvalidKey
	}
	return UnmarshalPublicKey(data)
}
func SavePublicKeyToFile(name string, key PublicKey) error {
	data, err := key.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(name, marshalPEM(PEM_TYPE_PUBLIC_KEY, data), 0644)
}

func LoadPrivateKeyFromFile(name string) (PrivateKey, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	dtype, data := unmarshalPEM(data)
	if dtype != PEM_TYPE_PRIVATE_KEY {
		return nil, ErrInvalidKey
	}
	return UnmarshalPrivateKey(data)
}
func SavePrivateKeyToFile(name string, key PrivateKey) error {
	data, err := key.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(name, marshalPEM(PEM_TYPE_PRIVATE_KEY, data), 0600)
}

func GenerateECCKey() (PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return PrivateKeyECC{key: priv}, nil
}

func GenerateECC384Key() (PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return PrivateKeyECC{key: priv}, nil
}

func GenerateRSAKey() (PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	return PrivateKeyRSA{key: priv}, nil
}
