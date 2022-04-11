package usecase

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/uoanlab/shenc/domain"
	"github.com/uoanlab/shenc/keys"
)

// TODO: implement functions

// GetNameByPublicKey
// GetNameByFingerprint(PublicKeyと統合する)
// GetFingerprintByName(そもそもいるのか)

// NewEncFile (domainに入れる)
// verify (domainに入れる、ファイル読み込み時に行う、オーナーチェックは別でおこなう)
// Permissionチェック入れる、手順確認
// ヘッダー全てがハッシュに含まれる
// IsEncFile

type KeyStore struct {
	Confd string // App config directory

	Keyd    string // Owner's key directory
	Pubkeyf string // Owner's public key file
	Prvkeyf string // Owner's private key file

	Knownkeyd string // Known (member's) keys directory
	Keylistf  string // Known (member's) list

	Filed string // file data directory

	keyList map[string]string
}

const (
	confDir = ".shenc"

	keyDir     = "keys"
	pubKeyFile = "owner.pem"
	prvKeyFile = "owner.key"

	knownKeyDir      = "knownkeys"
	knownKeyListFile = "list.dat"

	fileDir = "files"

	myFilePubKeyFile  = "my.pem"
	myFilePrivKeyFile = "my.key"
	fileKeyListFile   = "keylist"
	revisionListFile  = "revlist"
)

var ErrNotDir = errors.New("not a directory")
var ErrNotFile = errors.New("not a regular file")
var ErrBadPermission = errors.New("bad file/dir permission")
var ErrPrivateKeyNotFound = errors.New("private key not found")
var ErrInvalidData = errors.New("invalid data")

// NewKeyStore creates a new KeyStore instance.
// If conf dir is not exist, creates it.
// If private key is not exist, return store with ErrPrivateKeyNotFound.
func NewKeyStore() (KeyStore, error) {
	checkDir := func(dir string) (bool, error) {
		fi, err := os.Stat(dir)
		if os.IsNotExist(err) {
			return false, nil
		} else if err != nil {
			return false, err
		}
		if !fi.IsDir() {
			return false, ErrNotDir
		}
		return true, nil
	}

	s := KeyStore{}
	home, err := homedir.Dir()
	if err != nil {
		return s, err
	}

	// ~/.shenc
	s.Confd = path.Join(home, confDir)
	if env := os.Getenv("SHENCDIR"); env != "" {
		s.Confd = env
	}
	ok, err := checkDir(s.Confd)
	if err != nil {
		return s, err
	}
	if !ok {
		err = os.MkdirAll(s.Confd, 0755)
		if err != nil {
			return s, err
		}
	}

	// ~/.shenc/keys
	s.Keyd = path.Join(s.Confd, keyDir)
	ok, err = checkDir(s.Keyd)
	if err != nil {
		return s, err
	}
	if !ok {
		err = os.MkdirAll(s.Keyd, 0755)
		if err != nil {
			return s, err
		}
	}

	// ~/.shenc/keys/owner.pem
	s.Pubkeyf = path.Join(s.Keyd, pubKeyFile)

	// ~/.shenc/keys/owner.key
	s.Prvkeyf = path.Join(s.Keyd, prvKeyFile)

	// Check owner's key files
	privkeynotfound := false
	// private key
	fi, err := os.Stat(s.Prvkeyf)
	if os.IsNotExist(err) {
		privkeynotfound = true
	} else if err != nil {
		return s, err
	} else if fi.IsDir() {
		return s, ErrNotFile
		// } else if fi.Mode().Perm() != 0600 {
		// 	return s, ErrBadPermission
	}

	// public key
	fi, err = os.Stat(s.Pubkeyf)
	if os.IsNotExist(err) {
		if !privkeynotfound {
			privkey, err := keys.LoadPrivateKeyFromFile(s.Prvkeyf)
			if err != nil {
				return s, err
			}
			err = keys.SavePublicKeyToFile(s.Pubkeyf, privkey.Public())
			if err != nil {
				return s, err
			}
		}
	} else if err != nil {
		return s, err
	} else if fi.IsDir() {
		return s, ErrNotFile
	}

	// ~/.shenc/knownkeys
	s.Knownkeyd = path.Join(s.Confd, knownKeyDir)
	ok, err = checkDir(s.Knownkeyd)
	if err != nil {
		return s, err
	}
	if !ok {
		err = os.MkdirAll(s.Knownkeyd, 0755)
		if err != nil {
			return s, err
		}
	}

	// ~/.shenc/knownkeys/list.dat
	s.Keylistf = path.Join(s.Knownkeyd, knownKeyListFile)
	fi, err = os.Stat(s.Keylistf)
	if os.IsNotExist(err) {
		err = ioutil.WriteFile(s.Keylistf, []byte(""), 0644)
		if err != nil {
			return s, err
		}
	} else if err != nil {
		return s, err
	} else if fi.IsDir() {
		return s, ErrNotFile
	}

	// ~/.shenc/files
	s.Filed = path.Join(s.Confd, fileDir)
	ok, err = checkDir(s.Filed)
	if err != nil {
		return s, err
	}
	if !ok {
		err = os.MkdirAll(s.Filed, 0755)
		if err != nil {
			return s, err
		}
	}

	// Load known key list
	raw, err := ioutil.ReadFile(s.Keylistf)
	if err != nil {
		return s, err
	}
	dat := strings.Split(string(raw), "\n")
	s.keyList = make(map[string]string)
	for _, v := range dat {
		if v == "" {
			continue
		}
		t := strings.SplitN(v, ":", 2)
		s.keyList[t[0]] = t[1]
	}

	// Succcess but key generation is needed
	if privkeynotfound {
		return s, ErrPrivateKeyNotFound
	}
	return s, nil
}

var ErrAlreadyExists = errors.New("already exists")

func (s *KeyStore) AddPublicKey(key keys.PublicKey, name string) error {
	fingerprint := fmt.Sprintf("%X", key.Fingerprint())

	// Check if already exists
	for k, v := range s.keyList {
		if k == fingerprint || v == name {
			return ErrAlreadyExists
		}
	}

	// Store new public key
	newkeyf := path.Join(s.Knownkeyd, fingerprint)
	err := keys.SavePublicKeyToFile(newkeyf, key)
	if err != nil {
		return err
	}
	s.keyList[fingerprint] = name

	// Update list file
	f, err := os.Create(s.Keylistf)
	if err != nil {
		return err
	}
	defer f.Close()
	for k, v := range s.keyList {
		_, err = fmt.Fprintf(f, "%s:%s\n", k, v)
		if err != nil {
			return err
		}
	}

	return nil
}
func (s *KeyStore) RemovePublicKey(fingerprint string) error {
	// Delete from list
	delete(s.keyList, fingerprint)

	// Update list file
	f, err := os.Create(s.Keylistf)
	if err != nil {
		return err
	}
	defer f.Close()
	for k, v := range s.keyList {
		_, err = fmt.Fprintf(f, "%s:%s\n", k, v)
		if err != nil {
			return err
		}
	}

	// Delete public key file
	keyf := path.Join(s.Knownkeyd, fingerprint)
	err = os.Remove(keyf)
	if err != nil {
		return err
	}
	return nil
}
func (s *KeyStore) GetByName(name string) (keys.PublicKey, error) {
	for k, v := range s.keyList {
		if v == name {
			// Load public key
			keyf := path.Join(s.Knownkeyd, k)
			key, err := keys.LoadPublicKeyFromFile(keyf)
			if err != nil {
				return nil, err
			}
			return key, nil
		}
	}
	return nil, nil
}
func (s *KeyStore) GetByFingerprint(fingerprint string) (keys.PublicKey, error) {
	if _, ok := s.keyList[fingerprint]; !ok {
		return nil, nil
	}

	// Load public key
	keyf := path.Join(s.Knownkeyd, fingerprint)
	key, err := keys.LoadPublicKeyFromFile(keyf)
	if err != nil {
		return nil, err
	}
	return key, nil
}
func (s *KeyStore) GetMyPublicKey() (keys.PublicKey, error) {
	key, err := keys.LoadPublicKeyFromFile(s.Pubkeyf)
	if err != nil {
		return nil, err
	}
	return key, nil
}
func (s *KeyStore) GetMyPrivateKey() (keys.PrivateKey, error) {
	key, err := keys.LoadPrivateKeyFromFile(s.Prvkeyf)
	if err != nil {
		return nil, err
	}
	return key, nil
}
func (s *KeyStore) GetNameByFingerprint(fingerprint string) string {
	name, ok := s.keyList[fingerprint]
	if !ok {
		return ""
	}
	return name
}
func (s *KeyStore) AddFileKey(keylist domain.KeyListFile) error {
	keydecfunc := func(privkey keys.PrivateKey, dat []byte) ([]byte, error) {
		const sizeKey = 32
		const sizeIV = aes.BlockSize

		i := 0

		// Get enckey
		if len(dat) < 2 {
			return nil, ErrInvalidData
		}
		keysize := binary.LittleEndian.Uint16(dat[i : i+2])
		i += 2

		if len(dat) < int(keysize)+i {
			return nil, ErrInvalidData
		}
		keyiv, err := privkey.Decrypt(dat[i : i+int(keysize)])
		if err != nil {
			return nil, err
		}
		i += int(keysize)

		key := keyiv[:sizeKey]
		iv := keyiv[sizeKey : sizeKey+sizeIV]

		// Get data
		if len(dat) < 2+i {
			return nil, ErrInvalidData
		}
		datlen := int(binary.LittleEndian.Uint16(dat[i : i+2]))
		i += 2

		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		blkmd := cipher.NewCBCDecrypter(blk, iv)
		ebs := blkmd.BlockSize()
		sizewithpadding := datlen

		if datlen%ebs != 0 {
			sizewithpadding += ebs - (datlen % ebs)
		}
		if len(dat) != sizewithpadding+i {
			return nil, ErrInvalidData
		}
		res := make([]byte, sizewithpadding)
		blkmd.CryptBlocks(res, dat[i:])
		return res[:datlen], nil
	}

	fileid := fmt.Sprintf("%X", keylist.FileID)
	ownerfp := fmt.Sprintf("%X", keylist.Creator.FileKeyFingerprint)
	filedir := path.Join(s.Filed, fileid, ownerfp)

	// Save key list file
	keylistraw, err := keylist.Marshal()
	if err != nil {
		return err
	}
	err = os.MkdirAll(filedir, 0755)
	if err != nil {
		return err
	}

	file := path.Join(filedir, fileKeyListFile)
	_, err = os.Stat(file)
	if !os.IsNotExist(err) {
		return ErrAlreadyExists
	}
	err = ioutil.WriteFile(file, keylistraw, 0644)
	if err != nil {
		return err
	}

	// Extract my file keys
	myprivkey, err := s.GetMyPrivateKey()
	if err != nil {
		return err
	}

	var myfileprivkey keys.PrivateKey
	if bytes.Equal(keylist.Creator.Fingerprint[:], myprivkey.Public().Fingerprint()) {
		myfileprivkeyraw, err := keydecfunc(myprivkey, keylist.Creator.EncryptedFileKey) //myprivkey.Decrypt(keylist.Creator.EncryptedFileKey)
		if err != nil {
			return err
		}
		myfileprivkey, err = keys.UnmarshalPrivateKey(myfileprivkeyraw)
		if err != nil {
			return err
		}
	} else {
		for _, m := range keylist.Members {
			if bytes.Equal(m.Fingerprint[:], myprivkey.Public().Fingerprint()) {
				myfileprivkeyraw, err := keydecfunc(myprivkey, m.EncryptedFileKey) //myprivkey.Decrypt(m.EncryptedFileKey)
				if err != nil {
					return err
				}
				myfileprivkey, err = keys.UnmarshalPrivateKey(myfileprivkeyraw)
				if err != nil {
					return err
				}
				break
			}
		}
	}
	if myfileprivkey == nil {
		return errors.New("my file key not found")
	}

	// Save my file keys
	err = keys.SavePrivateKeyToFile(path.Join(filedir, myFilePrivKeyFile), myfileprivkey)
	if err != nil {
		return err
	}
	err = keys.SavePublicKeyToFile(path.Join(filedir, myFilePubKeyFile), myfileprivkey.Public())
	if err != nil {
		return err
	}

	return nil
}
func (s *KeyStore) GetFileKey(fileid, ownerfp string) (keys.PrivateKey, error) {
	keyd := path.Join(s.Filed, fileid, ownerfp)
	fi, err := os.Stat(keyd)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, ErrNotDir
	}

	// Load my file keys
	myfileprivkey, err := keys.LoadPrivateKeyFromFile(path.Join(keyd, myFilePrivKeyFile))

	return myfileprivkey, nil
}
