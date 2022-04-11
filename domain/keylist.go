package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/uoanlab/shenc/keys"
)

type KeyListUserInfo struct {
	Fingerprint        [32]byte
	FileKeyFingerprint [32]byte
	EncryptedFileKey   []byte
}
type KeyListFile struct {
	Version    int
	FileID     [16]byte
	UpdateTime time.Time
	Creator    KeyListUserInfo
	Members    []KeyListUserInfo
	Signature  []byte
}

var keyListMagicCode = [6]byte{0, 's', 'e', 'k', 'e', 'y'}

func (k *KeyListFile) marshalWithoutSign() ([]byte, error) {
	ret := []byte{}

	// Magic code
	ret = append(ret, keyListMagicCode[:]...)

	// Version
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf[:2], uint16(k.Version))
	ret = append(ret, buf...)

	// File ID
	ret = append(ret, k.FileID[:]...)

	// Update time
	buf = make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(k.UpdateTime.Unix()))
	ret = append(ret, buf...)

	// Creator
	// Fingerprint
	ret = append(ret, k.Creator.Fingerprint[:]...)
	// File key fingerprint
	ret = append(ret, k.Creator.FileKeyFingerprint[:]...)
	enckeyraw := k.Creator.EncryptedFileKey
	// File key size
	buf = make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(enckeyraw)))
	ret = append(ret, buf...)
	// File key
	ret = append(ret, enckeyraw...)
	// Padding
	if len(enckeyraw)%4 != 0 {
		ret = append(ret, make([]byte, 4-len(enckeyraw)%4)...)
	}

	// Members
	// Number of members
	buf = make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(k.Members)))
	ret = append(ret, buf...)
	// Members' info
	for _, m := range k.Members {
		// Fingerprint
		ret = append(ret, m.Fingerprint[:]...)
		// File key fingerprint
		ret = append(ret, m.FileKeyFingerprint[:]...)
		enckeyraw := m.EncryptedFileKey
		// File key size
		buf = make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(len(enckeyraw)))
		ret = append(ret, buf...)
		// File key
		ret = append(ret, enckeyraw...)
		// Padding
		if len(enckeyraw)%4 != 0 {
			ret = append(ret, make([]byte, 4-len(enckeyraw)%4)...)
		}
	}

	return ret, nil
}
func (k *KeyListFile) Marshal() ([]byte, error) {
	ret, err := k.marshalWithoutSign()
	if err != nil {
		return nil, err
	}

	// Size of signature
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(k.Signature)))
	ret = append(ret, buf...)

	// Signature
	ret = append(ret, k.Signature...)

	// Padding
	if len(k.Signature)%4 != 0 {
		ret = append(ret, make([]byte, 4-len(k.Signature)%4)...)
	}

	return ret, nil
}
func (k *KeyListFile) Sign(privkey keys.PrivateKey) error {
	buf, err := k.marshalWithoutSign()
	if err != nil {
		return err
	}
	hash := sha256.Sum256(buf)
	k.Signature, err = privkey.Sign(hash[:])
	return err
}
func (k *KeyListFile) Verify(pubkey keys.PublicKey) error {
	buf, err := k.marshalWithoutSign()
	if err != nil {
		return err
	}
	hash := sha256.Sum256(buf)
	return pubkey.Verify(hash[:], k.Signature)
}

var ErrInvalidKeyListFile = errors.New("invalid key list file")

func UnmarshalKeyListFile(data []byte) (KeyListFile, error) {
	k := KeyListFile{}
	i := 0

	// Magic code, version, file ID, update time
	if len(data) < 6+2+16+8 {
		return k, ErrInvalidKeyListFile
	}
	// Check magic code
	if !bytes.Equal(data[i:i+6], keyListMagicCode[:]) {
		return k, ErrInvalidKeyListFile
	}
	i += 6

	// Version
	k.Version = int(binary.LittleEndian.Uint16(data[i : i+2]))
	i += 2

	// File ID
	copy(k.FileID[:], data[i:i+16])
	i += 16

	// Update time
	k.UpdateTime = time.Unix(int64(binary.LittleEndian.Uint64(data[i:i+8])), 0)
	i += 8

	// Creator
	if len(data) < i+32+32+4 {
		return k, ErrInvalidKeyListFile
	}
	// Fingerprint
	copy(k.Creator.Fingerprint[:], data[i:i+32])
	i += 32

	// File key fingerprint
	copy(k.Creator.FileKeyFingerprint[:], data[i:i+32])
	i += 32

	// File key size
	enckeylen := binary.LittleEndian.Uint32(data[i : i+4])
	i += 4

	// File key
	if len(data) < i+int(enckeylen) {
		return k, ErrInvalidKeyListFile
	}
	k.Creator.EncryptedFileKey = data[i : i+int(enckeylen)]
	i += int(enckeylen)

	// Padding
	if enckeylen%4 != 0 {
		if len(data) < i+4-int(enckeylen)%4 {
			return k, ErrInvalidKeyListFile
		}
		i += 4 - int(enckeylen)%4
	}

	// Members
	if len(data) < i+4 {
		return k, ErrInvalidKeyListFile
	}
	num := binary.LittleEndian.Uint32(data[i : i+4])
	i += 4
	for j := uint32(0); j < num; j++ {
		if len(data) < i+32+32+4 {
			return k, ErrInvalidKeyListFile
		}
		m := KeyListUserInfo{}
		// Fingerprint
		copy(m.Fingerprint[:], data[i:i+32])
		i += 32

		// File key fingerprint
		copy(m.FileKeyFingerprint[:], data[i:i+32])
		i += 32

		// File key size
		enckeylen := binary.LittleEndian.Uint32(data[i : i+4])
		i += 4

		// File key
		if len(data) < i+int(enckeylen) {
			return k, ErrInvalidKeyListFile
		}
		m.EncryptedFileKey = data[i : i+int(enckeylen)]
		i += int(enckeylen)

		// Padding
		if enckeylen%4 != 0 {
			if len(data) < i+4-int(enckeylen)%4 {
				return k, ErrInvalidKeyListFile
			}
			i += 4 - int(enckeylen)%4
		}
		k.Members = append(k.Members, m)
	}

	// Signature
	if len(data) < i+4 {
		return k, ErrInvalidKeyListFile
	}
	signlen := binary.LittleEndian.Uint32(data[i : i+4])
	i += 4
	if len(data) < i+int(signlen) {
		return k, ErrInvalidKeyListFile
	}
	k.Signature = data[i : i+int(signlen)]
	i += int(signlen)

	// Padding
	if signlen%4 != 0 {
		if len(data) < i+4-int(signlen)%4 {
			return k, ErrInvalidKeyListFile
		}
		i += 4 - int(signlen)%4
	}

	return k, nil
}
