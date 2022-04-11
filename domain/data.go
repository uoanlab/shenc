package domain

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/uoanlab/shenc/keys"
)

// EncFile is encrypt file structure
type Data struct {
	Header Header

	OwnerEncShKey  []byte
	MemberEncShKey [][]byte

	PreviousFileHash [32]byte

	UpdateTime         time.Time
	UpdaterFingerprint [32]byte

	FileName string

	UpdaterSign []byte

	OrgFilePath string

	shkey []byte
	shiv  []byte

	Hash [32]byte
}

const (
	sizeKey = 32
	sizeIV  = aes.BlockSize
)

var (
	ErrInvalidFile      = errors.New("invalid file")
	ErrKeyNotFound      = errors.New("key not found")
	ErrPermissionDenied = errors.New("permission denied")
)

func (d *Data) RotateShKey() error {
	shkey := make([]byte, sizeKey)
	for {
		_, err := rand.Read(shkey)
		if err != nil {
			return err
		}
		if shkey[0] != 0 {
			break
		}
	}

	shiv := make([]byte, sizeIV)
	for {
		_, err := rand.Read(shiv)
		if err != nil {
			return err
		}
		if shiv[0] != 0 {
			break
		}
	}

	shkeyiv := append(shkey, shiv...)
	// Encrypt with owner's pub key
	encshkeyiv, err := d.Header.OwnerInfo.PublicKey.Encrypt(shkeyiv)
	if err != nil {
		return err
	}
	d.OwnerEncShKey = encshkeyiv

	// Encrypt with member's pub key
	d.MemberEncShKey = make([][]byte, len(d.Header.MemberInfo))
	for i, v := range d.Header.MemberInfo {
		// Exclude members who don't have read permission
		if v.Permission&PermRead == 0 {
			continue
		}
		encshkeyiv, err := v.PublicKey.Encrypt(shkeyiv)
		if err != nil {
			return err
		}
		d.MemberEncShKey[i] = encshkeyiv
	}

	d.shkey = shkey
	d.shiv = shiv
	return nil
}

// SignAndMarshal signs the data, marshal it and write to writer w.
// privkey is private key to sign
func (d *Data) SignAndMarshal(privkey keys.PrivateKey, w io.Writer) error {
	// check user's permission
	mypubkey := privkey.Public()
	pubkey := d.Header.OwnerInfo.PublicKey
	// check if user is owner
	if !bytes.Equal(mypubkey.Fingerprint(), pubkey.Fingerprint()) {
		// check if user is member
		ok := false
		n, foundm := d.Header.FindMember(pubkey.Fingerprint())
		if n < 0 {
			return ErrPermissionDenied
		}
		for _, m := range foundm {
			pubkey := m.PublicKey
			if bytes.Equal(mypubkey.Fingerprint(), pubkey.Fingerprint()) {
				if m.Permission&PermWrite == 0 {
					return ErrPermissionDenied
				}
				ok = true
				break
			}
		}
		if !ok {
			return ErrPermissionDenied
		}
	}

	hash := sha256.New()
	mw := io.MultiWriter(w, hash)

	if d.Header.rawdata == nil {
		return ErrInvalidHeader
	}
	_, err := mw.Write(d.Header.rawdata)
	if err != nil {
		return err
	}

	// OwnerEncShKey
	buf := make([]byte, 4)
	shkeysize := len(d.OwnerEncShKey)
	binary.LittleEndian.PutUint32(buf, uint32(shkeysize))
	_, err = mw.Write(buf)
	if err != nil {
		return err
	}
	_, err = mw.Write(d.OwnerEncShKey)
	if err != nil {
		return err
	}
	//padding
	if shkeysize%4 != 0 {
		padding := 4 - shkeysize%4
		buf := make([]byte, padding)
		_, err = mw.Write(buf)
		if err != nil {
			return err
		}
	}

	// MemberEncShKey
	for _, v := range d.MemberEncShKey {
		shkeysize = len(v)
		binary.LittleEndian.PutUint32(buf, uint32(shkeysize))
		_, err = mw.Write(buf)
		if err != nil {
			return err
		}
		_, err = mw.Write(v)
		if err != nil {
			return err
		}
		//padding
		if shkeysize%4 != 0 {
			padding := 4 - shkeysize%4
			buf := make([]byte, padding)
			_, err = mw.Write(buf)
			if err != nil {
				return err
			}
		}
	}

	// PreviousFileHash
	_, err = mw.Write(d.PreviousFileHash[:])
	if err != nil {
		return err
	}

	// UpdateTime
	buf = make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(d.UpdateTime.Unix()))
	_, err = mw.Write(buf)
	if err != nil {
		return err
	}

	// UpdaterFingerprint
	_, err = mw.Write(d.UpdaterFingerprint[:])
	if err != nil {
		return err
	}

	// File name size
	filenamesize := len(d.FileName)
	binary.LittleEndian.PutUint32(buf, uint32(filenamesize))
	_, err = mw.Write(buf[:4])
	if err != nil {
		return err
	}

	// Prepare encrypter
	blk, err := aes.NewCipher(d.shkey)
	if err != nil {
		return err
	}
	blkmd := cipher.NewCBCEncrypter(blk, d.shiv)
	ebs := blkmd.BlockSize()

	//Encrypt file name
	// buffer size should be multiple of block size
	filenamesizewithpad := filenamesize
	// padding
	if filenamesizewithpad%ebs != 0 {
		filenamesizewithpad += ebs - (filenamesizewithpad % ebs)
	}
	buf = make([]byte, filenamesizewithpad)

	copy(buf, []byte(d.FileName))
	rand.Read(buf[filenamesize:])

	blkmd.CryptBlocks(buf, buf)

	// File name
	_, err = mw.Write(buf)
	if err != nil {
		return err
	}

	// File size
	file, err := os.Open(d.OrgFilePath)
	if err != nil {
		return err
	}
	fileinfo, err := file.Stat()
	if err != nil {
		return err
	}
	filesize := fileinfo.Size()
	buf = make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(filesize))
	_, err = mw.Write(buf)
	if err != nil {
		return err
	}

	// Prepare encrypter
	blk, err = aes.NewCipher(d.shkey)
	if err != nil {
		return err
	}
	blkmd = cipher.NewCBCEncrypter(blk, d.shiv)
	ebs = blkmd.BlockSize()

	// Encrypt file
	// buffer size should be multiple of block size
	filesizewithpadding := filesize
	// padding
	if filesizewithpadding%int64(ebs) != 0 {
		filesizewithpadding += int64(ebs) - (filesize % int64(ebs))
	}

	sizeEncUnit := 4096
	bufsize := sizeEncUnit
	if bufsize%ebs != 0 {
		bufsize += ebs - (bufsize % ebs)
	}

	buf = make([]byte, bufsize)

	n := 0
	i := int64(0)
	for i < filesizewithpadding {
		n, err = file.Read(buf)
		if err != nil {
			return err
		}
		if n < bufsize {
			padding := 0
			if n%ebs != 0 {
				padding = ebs - (n % ebs)
			}
			_, err = rand.Read(buf[n : n+padding])
			if err != nil {
				return err
			}
			n += padding
		}

		blkmd.CryptBlocks(buf[:n], buf[:n])

		_, err = mw.Write(buf[:n])
		if err != nil {
			return err
		}
		i += int64(n)
	}

	// UpdaterSign
	hashraw := hash.Sum(nil)
	copy(d.Hash[:], hashraw[:])
	d.UpdaterSign, err = privkey.Sign(hashraw)
	if err != nil {
		return err
	}
	signsize := len(d.UpdaterSign)
	binary.Write(w, binary.LittleEndian, uint32(signsize))
	_, err = w.Write(d.UpdaterSign)
	if err != nil {
		return err
	}
	//padding
	if signsize%4 != 0 {
		padding := 4 - signsize%4
		buf := make([]byte, padding)
		_, err = w.Write(buf)
		if err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalAndVerify decrypts and verifies the data
func (d *Data) Unmarshal(r io.Reader, decDst string, privkey keys.PrivateKey) error {
	hash := sha256.New()

	_, err := d.Header.UnmarshalAndVerify(r)
	if err != nil {
		return err
	}
	_, err = hash.Write(d.Header.rawdata)
	if err != nil {
		return err
	}

	// OwnerEncShKey
	// size
	buf := make([]byte, 4)
	n, err := r.Read(buf)
	if err != nil {
		return err
	}
	_, err = hash.Write(buf[:n])
	if err != nil {
		return err
	}
	if n < 4 {
		return ErrInvalidFile
	}
	shkeysize := binary.LittleEndian.Uint32(buf)
	// padding
	shkeysizewithpadder := shkeysize
	if shkeysizewithpadder%4 != 0 {
		shkeysizewithpadder += 4 - (shkeysizewithpadder % 4)
	}

	buf = make([]byte, shkeysizewithpadder)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	_, err = hash.Write(buf[:n])
	if err != nil {
		return err
	}
	if n < int(shkeysizewithpadder) {
		return ErrInvalidFile
	}
	d.OwnerEncShKey = buf[:shkeysize]

	// MemberEncShKey
	d.MemberEncShKey = make([][]byte, len(d.Header.MemberInfo))
	for i := 0; i < len(d.Header.MemberInfo); i++ {
		// size
		buf = make([]byte, 4)
		n, err = r.Read(buf)
		if err != nil {
			return err
		}
		_, err = hash.Write(buf[:n])
		if err != nil {
			return err
		}
		if n < 4 {
			return ErrInvalidFile
		}
		shkeysize = binary.LittleEndian.Uint32(buf)
		// padding
		shkeysizewithpadder = shkeysize
		if shkeysizewithpadder%4 != 0 {
			shkeysizewithpadder += 4 - (shkeysizewithpadder % 4)
		}

		buf = make([]byte, shkeysizewithpadder)
		n, err = r.Read(buf)
		if err != nil {
			return err
		}
		_, err = hash.Write(buf[:n])
		if err != nil {
			return err
		}
		if n < int(shkeysizewithpadder) {
			return ErrInvalidFile
		}
		d.MemberEncShKey[i] = buf[:shkeysize]
	}

	// PreviousFileHash
	n, err = r.Read(d.PreviousFileHash[:])
	if err != nil {
		return err
	}
	_, err = hash.Write(d.PreviousFileHash[:n])
	if err != nil {
		return err
	}
	if n < 32 {
		return ErrInvalidFile
	}

	// UpdateTime
	buf = make([]byte, 8)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	_, err = hash.Write(buf[:n])
	if err != nil {
		return err
	}
	if n < 8 {
		return ErrInvalidFile
	}
	d.UpdateTime = time.Unix(int64(binary.LittleEndian.Uint64(buf)), 0)

	// UpdaterFingerprint
	n, err = r.Read(d.UpdaterFingerprint[:])
	if err != nil {
		return err
	}
	_, err = hash.Write(d.UpdaterFingerprint[:n])
	if err != nil {
		return err
	}
	if n < 32 {
		return ErrInvalidFile
	}

	//Decrypt shkey
	myfp := privkey.Public().Fingerprint()
	fp := d.Header.OwnerInfo.PublicKey.Fingerprint()
	if bytes.Equal(d.Header.OwnerInfo.Fingerprint[:], myfp[:12]) && bytes.Equal(fp, myfp) {
		shkeyiv, err := privkey.Decrypt(d.OwnerEncShKey)
		if err != nil {
			return err
		}
		d.shkey = shkeyiv[:sizeKey]
		d.shiv = shkeyiv[sizeKey:]
	} else {
		n, foundm := d.Header.FindMember(myfp)
		if n < 0 {
			return ErrPermissionDenied
		}
		for i, m := range foundm {
			if bytes.Equal(m.PublicKey.Fingerprint(), myfp) {
				if m.Permission&PermRead == 0 {
					return ErrPermissionDenied
				}
				shkeyiv, err := privkey.Decrypt(d.MemberEncShKey[n+i])
				if err != nil {
					return err
				}
				d.shkey = shkeyiv[:sizeKey]
				d.shiv = shkeyiv[sizeKey:]
				break
			}
		}
	}
	if d.shkey == nil {
		return ErrPermissionDenied
	}
	// FileName
	// size
	buf = make([]byte, 4)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	_, err = hash.Write(buf[:n])
	if err != nil {
		return err
	}
	if n < 4 {
		return ErrInvalidFile
	}
	filenamesize := binary.LittleEndian.Uint32(buf)

	// decrypter
	blk, err := aes.NewCipher(d.shkey)
	if err != nil {
		return err
	}
	blkmd := cipher.NewCBCDecrypter(blk, d.shiv)
	ebs := blkmd.BlockSize()

	// padding
	filenamesizewithpadder := filenamesize
	if filenamesizewithpadder%uint32(ebs) != 0 {
		filenamesizewithpadder += uint32(ebs) - (filenamesizewithpadder % uint32(ebs))
	}

	buf = make([]byte, filenamesizewithpadder)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	_, err = hash.Write(buf[:n])
	if err != nil {
		return err
	}
	if n < int(filenamesizewithpadder) {
		return ErrInvalidFile
	}

	blkmd.CryptBlocks(buf, buf)
	d.FileName = string(buf[:filenamesize])

	// Prepare decrypt file
	var decfile *os.File
	if decDst != "" {
		d.OrgFilePath = path.Join(decDst, d.FileName)
		_, err = os.Stat(d.OrgFilePath)
		if err == nil {
			return errors.New("file already exists")
		}
		decfile, err = os.Create(d.OrgFilePath)
		if err != nil {
			return err
		}
		defer decfile.Close()
	}
	// FileSize
	buf = make([]byte, 8)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	_, err = hash.Write(buf[:n])
	if err != nil {
		return err
	}
	if n < 8 {
		return ErrInvalidFile
	}
	filesize := int64(binary.LittleEndian.Uint64(buf))

	// decrypter
	blk, err = aes.NewCipher(d.shkey)
	if err != nil {
		return err
	}
	blkmd = cipher.NewCBCDecrypter(blk, d.shiv)
	ebs = blkmd.BlockSize()

	// padding
	filesizewithpadding := filesize
	if filesizewithpadding%int64(ebs) != 0 {
		filesizewithpadding += int64(ebs) - (filesizewithpadding % int64(ebs))
	}

	// DecryptFile
	sizeDecUnit := 4096
	bufsize := sizeDecUnit
	if bufsize%ebs != 0 {
		bufsize += ebs - (bufsize % ebs)
	}

	buf = make([]byte, bufsize)

	i := int64(0)
	for i < filesizewithpadding {
		if i+int64(bufsize) > filesizewithpadding {
			bufsize = int(filesizewithpadding - i)
		}
		n, err = r.Read(buf[:bufsize])
		if err != nil {
			return err
		}
		_, err = hash.Write(buf[:n])
		if err != nil {
			return err
		}
		if n%ebs != 0 {
			return ErrInvalidFile
		}
		i += int64(n)

		blkmd.CryptBlocks(buf, buf)

		if i == filesizewithpadding {
			n -= int(filesizewithpadding - filesize)
		}
		if decfile != nil {
			_, err = decfile.Write(buf[:n])
			if err != nil {
				return err
			}
		}
	}

	// UpdaterSign
	// size
	buf = make([]byte, 4)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	if n < 4 {
		return ErrInvalidFile
	}
	signsize := binary.LittleEndian.Uint32(buf)
	// padding
	signsizewithpadder := signsize
	if signsizewithpadder%4 != 0 {
		signsizewithpadder += 4 - (signsizewithpadder % 4)
	}

	buf = make([]byte, signsizewithpadder)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	if n < int(signsizewithpadder) {
		return ErrInvalidFile
	}
	d.UpdaterSign = buf[:signsize]

	// verify updater sign
	hashraw := hash.Sum(nil)

	copy(d.Hash[:], hashraw[:])
	ufp := d.UpdaterFingerprint[:]
	fp = d.Header.OwnerInfo.Fingerprint[:]
	if bytes.Equal(ufp[:12], fp[:12]) {
		fp = d.Header.OwnerInfo.PublicKey.Fingerprint()
		if bytes.Equal(ufp, fp) {
			// updater is owner
			err = d.Header.OwnerInfo.PublicKey.Verify(hashraw, d.UpdaterSign)
			if err != nil {
				return err
			}
			return nil
		}
	}

	n, foundm := d.Header.FindMember(ufp)
	if n < 0 {
		return ErrInvalidFile
	}
	for _, m := range foundm {
		fp = m.PublicKey.Fingerprint()
		if bytes.Equal(ufp, fp) {
			// updater is one of members
			if m.Permission&PermWrite == 0 {
				return ErrInvalidFile
			}
			err = m.PublicKey.Verify(hashraw, d.UpdaterSign)
			if err != nil {
				return err
			}
			return nil
		}
	}

	return ErrInvalidFile
}

// UnmarshalAndVerify decrypts and verifies the data
func (d *Data) UnmarshalAndVerify(r io.Reader, decDst string, findPrivkey func(fileid, ownerid string) keys.PrivateKey) error {
	hash := sha256.New()

	_, err := d.Header.UnmarshalAndVerify(r)
	if err != nil {
		return err
	}
	_, err = hash.Write(d.Header.rawdata)
	if err != nil {
		return err
	}

	ownerfp := d.Header.OwnerInfo.PublicKey.Fingerprint()
	privkey := findPrivkey(fmt.Sprintf("%X", d.Header.UUID), fmt.Sprintf("%X", ownerfp))
	if privkey == nil {
		return ErrKeyNotFound
	}

	// OwnerEncShKey
	// size
	buf := make([]byte, 4)
	n, err := r.Read(buf)
	if err != nil {
		return err
	}
	_, err = hash.Write(buf[:n])
	if err != nil {
		return err
	}
	if n < 4 {
		return ErrInvalidFile
	}
	shkeysize := binary.LittleEndian.Uint32(buf)
	// padding
	shkeysizewithpadder := shkeysize
	if shkeysizewithpadder%4 != 0 {
		shkeysizewithpadder += 4 - (shkeysizewithpadder % 4)
	}

	buf = make([]byte, shkeysizewithpadder)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	_, err = hash.Write(buf[:n])
	if err != nil {
		return err
	}
	if n < int(shkeysizewithpadder) {
		return ErrInvalidFile
	}
	d.OwnerEncShKey = buf[:shkeysize]

	// MemberEncShKey
	d.MemberEncShKey = make([][]byte, len(d.Header.MemberInfo))
	for i := 0; i < len(d.Header.MemberInfo); i++ {
		// size
		buf = make([]byte, 4)
		n, err = r.Read(buf)
		if err != nil {
			return err
		}
		_, err = hash.Write(buf[:n])
		if err != nil {
			return err
		}
		if n < 4 {
			return ErrInvalidFile
		}
		shkeysize = binary.LittleEndian.Uint32(buf)
		// padding
		shkeysizewithpadder = shkeysize
		if shkeysizewithpadder%4 != 0 {
			shkeysizewithpadder += 4 - (shkeysizewithpadder % 4)
		}

		buf = make([]byte, shkeysizewithpadder)
		n, err = r.Read(buf)
		if err != nil {
			return err
		}
		_, err = hash.Write(buf[:n])
		if err != nil {
			return err
		}
		if n < int(shkeysizewithpadder) {
			return ErrInvalidFile
		}
		d.MemberEncShKey[i] = buf[:shkeysize]
	}

	// PreviousFileHash
	n, err = r.Read(d.PreviousFileHash[:])
	if err != nil {
		return err
	}
	_, err = hash.Write(d.PreviousFileHash[:n])
	if err != nil {
		return err
	}
	if n < 32 {
		return ErrInvalidFile
	}

	// UpdateTime
	buf = make([]byte, 8)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	_, err = hash.Write(buf[:n])
	if err != nil {
		return err
	}
	if n < 8 {
		return ErrInvalidFile
	}
	d.UpdateTime = time.Unix(int64(binary.LittleEndian.Uint64(buf)), 0)

	// UpdaterFingerprint
	n, err = r.Read(d.UpdaterFingerprint[:])
	if err != nil {
		return err
	}
	_, err = hash.Write(d.UpdaterFingerprint[:n])
	if err != nil {
		return err
	}
	if n < 32 {
		return ErrInvalidFile
	}

	//Decrypt shkey
	myfp := privkey.Public().Fingerprint()
	fp := d.Header.OwnerInfo.PublicKey.Fingerprint()
	if bytes.Equal(d.Header.OwnerInfo.Fingerprint[:], myfp[:12]) && bytes.Equal(fp, myfp) {
		shkeyiv, err := privkey.Decrypt(d.OwnerEncShKey)
		if err != nil {
			return err
		}
		d.shkey = shkeyiv[:sizeKey]
		d.shiv = shkeyiv[sizeKey:]
	} else {
		n, foundm := d.Header.FindMember(myfp)
		if n < 0 {
			return ErrPermissionDenied
		}
		for i, m := range foundm {
			if bytes.Equal(m.PublicKey.Fingerprint(), myfp) {
				if m.Permission&PermRead == 0 {
					return ErrPermissionDenied
				}
				shkeyiv, err := privkey.Decrypt(d.MemberEncShKey[n+i])
				if err != nil {
					return err
				}
				d.shkey = shkeyiv[:sizeKey]
				d.shiv = shkeyiv[sizeKey:]
				break
			}
		}
	}
	if d.shkey == nil {
		return ErrPermissionDenied
	}
	// FileName
	// size
	buf = make([]byte, 4)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	_, err = hash.Write(buf[:n])
	if err != nil {
		return err
	}
	if n < 4 {
		return ErrInvalidFile
	}
	filenamesize := binary.LittleEndian.Uint32(buf)

	// decrypter
	blk, err := aes.NewCipher(d.shkey)
	if err != nil {
		return err
	}
	blkmd := cipher.NewCBCDecrypter(blk, d.shiv)
	ebs := blkmd.BlockSize()

	// padding
	filenamesizewithpadder := filenamesize
	if filenamesizewithpadder%uint32(ebs) != 0 {
		filenamesizewithpadder += uint32(ebs) - (filenamesizewithpadder % uint32(ebs))
	}

	buf = make([]byte, filenamesizewithpadder)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	_, err = hash.Write(buf[:n])
	if err != nil {
		return err
	}
	if n < int(filenamesizewithpadder) {
		return ErrInvalidFile
	}

	blkmd.CryptBlocks(buf, buf)
	d.FileName = string(buf[:filenamesize])

	// Prepare decrypt file
	var decfile *os.File
	if decDst != "" {
		d.OrgFilePath = path.Join(decDst, d.FileName)
		_, err = os.Stat(d.OrgFilePath)
		if err == nil {
			return errors.New("file already exists")
		}
		decfile, err = os.Create(d.OrgFilePath)
		if err != nil {
			return err
		}
		defer decfile.Close()
	}
	// FileSize
	buf = make([]byte, 8)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	_, err = hash.Write(buf[:n])
	if err != nil {
		return err
	}
	if n < 8 {
		return ErrInvalidFile
	}
	filesize := int64(binary.LittleEndian.Uint64(buf))

	// decrypter
	blk, err = aes.NewCipher(d.shkey)
	if err != nil {
		return err
	}
	blkmd = cipher.NewCBCDecrypter(blk, d.shiv)
	ebs = blkmd.BlockSize()

	// padding
	filesizewithpadding := filesize
	if filesizewithpadding%int64(ebs) != 0 {
		filesizewithpadding += int64(ebs) - (filesizewithpadding % int64(ebs))
	}

	// DecryptFile
	sizeDecUnit := 4096
	bufsize := sizeDecUnit
	if bufsize%ebs != 0 {
		bufsize += ebs - (bufsize % ebs)
	}

	buf = make([]byte, bufsize)

	i := int64(0)
	for i < filesizewithpadding {
		if i+int64(bufsize) > filesizewithpadding {
			bufsize = int(filesizewithpadding - i)
		}
		n, err = r.Read(buf[:bufsize])
		if err != nil {
			return err
		}
		_, err = hash.Write(buf[:n])
		if err != nil {
			return err
		}
		if n%ebs != 0 {
			return ErrInvalidFile
		}
		i += int64(n)

		blkmd.CryptBlocks(buf, buf)

		if i == filesizewithpadding {
			n -= int(filesizewithpadding - filesize)
		}
		if decfile != nil {
			_, err = decfile.Write(buf[:n])
			if err != nil {
				return err
			}
		}
	}

	// UpdaterSign
	// size
	buf = make([]byte, 4)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	if n < 4 {
		return ErrInvalidFile
	}
	signsize := binary.LittleEndian.Uint32(buf)
	// padding
	signsizewithpadder := signsize
	if signsizewithpadder%4 != 0 {
		signsizewithpadder += 4 - (signsizewithpadder % 4)
	}

	buf = make([]byte, signsizewithpadder)
	n, err = r.Read(buf)
	if err != nil {
		return err
	}
	if n < int(signsizewithpadder) {
		return ErrInvalidFile
	}
	d.UpdaterSign = buf[:signsize]

	// verify updater sign
	hashraw := hash.Sum(nil)

	copy(d.Hash[:], hashraw[:])
	ufp := d.UpdaterFingerprint[:]
	fp = d.Header.OwnerInfo.Fingerprint[:]
	if bytes.Equal(ufp[:12], fp[:12]) {
		fp = d.Header.OwnerInfo.PublicKey.Fingerprint()
		if bytes.Equal(ufp, fp) {
			// updater is owner
			err = d.Header.OwnerInfo.PublicKey.Verify(hashraw, d.UpdaterSign)
			if err != nil {
				return err
			}
			return nil
		}
	}

	n, foundm := d.Header.FindMember(ufp)
	if n < 0 {
		return ErrInvalidFile
	}
	for _, m := range foundm {
		fp = m.PublicKey.Fingerprint()
		if bytes.Equal(ufp, fp) {
			// updater is one of members
			if m.Permission&PermWrite == 0 {
				return ErrInvalidFile
			}
			err = m.PublicKey.Verify(hashraw, d.UpdaterSign)
			if err != nil {
				return err
			}
			return nil
		}
	}

	return ErrInvalidFile
}

func (d *Data) DecryptShKey(privkey keys.PrivateKey) error {
	myfp := privkey.Public().Fingerprint()

	ownfp := d.Header.OwnerInfo.PublicKey.Fingerprint()
	if bytes.Equal(ownfp, myfp) {
		shkey, err := privkey.Decrypt(d.OwnerEncShKey)
		if err != nil {
			return err
		}
		d.shkey = shkey[:sizeKey]
		d.shiv = shkey[sizeKey:]
		return nil
	}

	for i, mempk := range d.Header.MemberInfo {
		memfp := mempk.PublicKey.Fingerprint()
		if bytes.Equal(memfp, myfp) {
			shkey, err := privkey.Decrypt(d.MemberEncShKey[i])
			if err != nil {
				return err
			}
			d.shkey = shkey[:sizeKey]
			d.shiv = shkey[sizeKey:]
			return nil
		}
	}

	return ErrPermissionDenied
}

func NewData() (*Data, error) {
	h, err := NewHeader()
	if err != nil {
		return nil, err
	}

	return &Data{
		Header: *h,
	}, nil
}
