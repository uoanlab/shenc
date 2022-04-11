package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/uoanlab/shenc/keys"
)

var MagicCode = [6]byte{0, 's', 'h', 'e', 'n', 'c'}

// Permission
type Perm uint16

const (
	PermRead  Perm = 0x01
	PermWrite Perm = 0x02
	PermFull  Perm = PermRead | PermWrite
	PermOwner Perm = 0xFFFF
)

var (
	ErrInvalidUserInfo    = errors.New("Invalid UserInfo")
	ErrInvalidHeader      = errors.New("invalid header")
	ErrUnsupportedVersion = errors.New("unsupported version")
)

// UserInfo is structure holding User's fingerprint, key, and permission information
type UserInfo struct {
	Permission  Perm
	Fingerprint [12]byte
	PublicKey   keys.PublicKey
}

// Header is header of encrypt file structure
type Header struct {
	// (Magic code)
	Version    uint16
	UUID       [16]byte
	CreateTime time.Time

	OwnerInfo  UserInfo
	MemberInfo []UserInfo

	SignTime  time.Time
	OwnerSign []byte

	rawdata []byte
}

// SignAndMarshal marshal header and sign it with given private key
// The private key should correspond to the public key of the owner
func (h *Header) SignAndMarshal(privkey keys.PrivateKey) ([]byte, error) {
	// Check the private key corresponds to the owner's public key
	ownpubkeyraw, err := h.OwnerInfo.PublicKey.Marshal()
	if err != nil {
		return nil, err
	}
	mypubkeyraw, err := privkey.Public().Marshal()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(ownpubkeyraw, mypubkeyraw) {
		return nil, ErrInvalidHeader
	}

	ret := []byte{}
	buf := make([]byte, 8)

	// Magic code
	ret = append(ret, MagicCode[:]...)

	// Version
	binary.LittleEndian.PutUint16(buf[:2], h.Version)
	ret = append(ret, buf[:2]...)

	// UUID
	ret = append(ret, h.UUID[:]...)

	// CreateTime
	binary.LittleEndian.PutUint64(buf, uint64(h.CreateTime.Unix()))
	ret = append(ret, buf...)

	// NumOfMember
	numofmember := uint16(len(h.MemberInfo))
	binary.LittleEndian.PutUint16(buf[:2], numofmember)
	ret = append(ret, buf[:2]...)

	// OwnerInfo
	// Public key size
	pubkeyraw, err := h.OwnerInfo.PublicKey.Marshal()
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint16(buf[:2], uint16(len(pubkeyraw)))
	ret = append(ret, buf[:2]...)

	// Fingerprint
	ret = append(ret, h.OwnerInfo.Fingerprint[:]...)

	// Public key
	ret = append(ret, pubkeyraw...)
	// padding
	if len(pubkeyraw)%4 != 0 {
		ret = append(ret, make([]byte, 4-len(pubkeyraw)%4)...)
	}

	// MemberInfo
	for _, v := range h.MemberInfo {
		// Permission
		binary.LittleEndian.PutUint16(buf[:2], uint16(v.Permission))
		ret = append(ret, buf[:2]...)

		// Public key size
		pubkeyraw, err := v.PublicKey.Marshal()
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint16(buf[:2], uint16(len(pubkeyraw)))
		ret = append(ret, buf[:2]...)

		// Fingerprint
		ret = append(ret, v.Fingerprint[:]...)

		// Public key
		ret = append(ret, pubkeyraw...)
		// padding
		if len(pubkeyraw)%4 != 0 {
			ret = append(ret, make([]byte, 4-len(pubkeyraw)%4)...)
		}
	}

	// ------------------------------------------------------------

	// SignTime
	h.SignTime = time.Now()
	binary.LittleEndian.PutUint64(buf, uint64(h.SignTime.Unix()))
	ret = append(ret, buf...)

	// sign
	hashraw := sha256.Sum256(ret)
	h.OwnerSign, err = privkey.Sign(hashraw[:])
	if err != nil {
		return nil, err
	}

	// Size of owner sign
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(h.OwnerSign)))
	ret = append(ret, buf[:4]...)

	// OwnerSign
	ret = append(ret, h.OwnerSign...)
	// Padding
	if len(h.OwnerSign)%4 != 0 {
		ret = append(ret, make([]byte, 4-len(h.OwnerSign)%4)...)
	}

	h.rawdata = ret
	return ret, nil
}

// Unmarshal unmarshal header from given reader and returns read bytes and error
func (h *Header) UnmarshalAndVerify(r io.Reader) (int, error) {
	i := 0

	// data size should be at least 6(magic code) + 2(version) + 16(uuid)
	// + 8(create time) + 2(num of member)
	buf := make([]byte, 6+2+16+8+2)
	n, err := r.Read(buf)
	if err != nil {
		return i, err
	}
	if n < 6+2+16+8+2 {
		return i, ErrInvalidHeader
	}

	// Magic code
	if !bytes.Equal(buf[:6], MagicCode[:]) {
		return i, ErrInvalidHeader
	}
	i += 6

	// Version
	h.Version = binary.LittleEndian.Uint16(buf[6:8])
	if h.Version != 2 {
		return i, ErrUnsupportedVersion
	}
	i += 2

	// UUID
	copy(h.UUID[:], buf[8:24])
	i += 16

	// CreateTime
	h.CreateTime = time.Unix(int64(binary.LittleEndian.Uint64(buf[24:32])), 0)
	i += 8

	// NumOfMember
	numofmember := binary.LittleEndian.Uint16(buf[32:34])
	i += 2

	h.rawdata = buf

	// OwnerInfo
	buf = make([]byte, 14)
	n, err = r.Read(buf)
	if err != nil {
		return i, err
	}
	// data size should be at least 2(key size) + 12(fingerprint)
	if n < 2+12 {
		return i, ErrInvalidUserInfo
	}

	// Public key size
	pubkeysize := binary.LittleEndian.Uint16(buf[:2])
	pubkeysizewithpad := pubkeysize
	if pubkeysize%4 != 0 {
		pubkeysizewithpad += (4 - pubkeysize%4)
	}
	i += 2

	u := UserInfo{}
	// Fingerprint
	u.Fingerprint = [12]byte{}
	copy(u.Fingerprint[:], buf[2:])
	i += 12

	h.rawdata = append(h.rawdata, buf...)

	buf = make([]byte, pubkeysizewithpad)
	n, err = r.Read(buf)
	if err != nil {
		return i, err
	}
	// Public key
	if n < int(pubkeysizewithpad) {
		return i, ErrInvalidUserInfo
	}
	u.PublicKey, err = keys.UnmarshalPublicKey(buf[:pubkeysize])
	if err != nil {
		return i, err
	}
	i += int(pubkeysizewithpad)

	h.OwnerInfo = u
	h.rawdata = append(h.rawdata, buf...)

	// MemberInfo
	h.MemberInfo = make([]UserInfo, numofmember)
	for j := 0; j < int(numofmember); j++ {
		buf = make([]byte, 16)
		n, err = r.Read(buf)
		if err != nil {
			return i, err
		}
		// data size should be at least 2(permission) + 2(key size) + 12(fingerprint)
		if n < 2+2+12 {
			return i, ErrInvalidUserInfo
		}

		// Permission
		u.Permission = Perm(binary.LittleEndian.Uint16(buf[:2]))
		i += 2

		// Public key size
		pubkeysize := binary.LittleEndian.Uint16(buf[2:4])
		pubkeysizewithpad := pubkeysize
		if pubkeysize%4 != 0 {
			pubkeysizewithpad += (4 - pubkeysize%4)
		}
		i += 2

		// Fingerprint
		copy(u.Fingerprint[:], buf[4:])
		i += 12

		h.rawdata = append(h.rawdata, buf...)

		buf = make([]byte, pubkeysizewithpad)
		n, err = r.Read(buf)
		if err != nil {
			return i, err
		}

		// Public key
		if n < int(pubkeysizewithpad) {
			return i, ErrInvalidUserInfo
		}
		u.PublicKey, err = keys.UnmarshalPublicKey(buf[:pubkeysize])
		if err != nil {
			return i, err
		}
		i += int(pubkeysizewithpad)
		h.rawdata = append(h.rawdata, buf...)

		h.MemberInfo[j] = u
	}

	buf = make([]byte, 12)
	n, err = r.Read(buf)
	if err != nil {
		return i, err
	}
	// data size should be at least 8(sign time) + 4(size of sign)
	if n < 8+4 {
		return i, ErrInvalidHeader
	}
	// SignTime
	h.SignTime = time.Unix(int64(binary.LittleEndian.Uint64(buf[:8])), 0)
	i += 8

	// Size of owner sign
	signsize := binary.LittleEndian.Uint32(buf[8:12])
	signsizewithpadding := signsize
	if signsize%4 != 0 {
		signsizewithpadding += 4 - signsize%4
	}
	i += 4
	h.rawdata = append(h.rawdata, buf...)

	buf = make([]byte, signsizewithpadding)
	n, err = r.Read(buf)
	if err != nil {
		return i, err
	}
	if n < int(signsizewithpadding) {
		return i, ErrInvalidHeader
	}
	// OwnerSign
	h.OwnerSign = buf[:signsize]
	i += int(signsizewithpadding)
	h.rawdata = append(h.rawdata, buf...)

	// verify owner sign
	hash := sha256.Sum256(h.rawdata[:len(h.rawdata)-4-int(signsizewithpadding)])
	err = h.OwnerInfo.PublicKey.Verify(hash[:], h.OwnerSign)
	if err != nil {
		return i, err
	}

	return i, nil
}

func NewHeader() (*Header, error) {
	res := &Header{
		Version: 2,
		// UUID:       [16]byte{},
		CreateTime: time.Now(),
	}
	u, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	uuid, err := u.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(res.UUID[:], uuid)

	return res, nil
}

func (h *Header) Sort() {
	sort.Slice(h.MemberInfo, func(i, j int) bool {
		return bytes.Compare(h.MemberInfo[i].Fingerprint[:], h.MemberInfo[j].Fingerprint[:]) < 0
	})
}

// FindMember finds a member by fingerprint and returns its first index and members.
// If not found, returns -1 and nil.
// FindMember may multiple members with the same partial fingerprint.
func (h *Header) FindMember(fingerprint []byte) (int, []UserInfo) {
	fingerprint = fingerprint[:12]
	l := sort.Search(len(h.MemberInfo), func(m int) bool {
		comp := bytes.Compare(fingerprint, h.MemberInfo[m].Fingerprint[:])
		return comp <= 0
	})
	if l == len(h.MemberInfo) {
		return -1, nil
	}
	r := sort.Search(len(h.MemberInfo), func(m int) bool {
		comp := bytes.Compare(fingerprint, h.MemberInfo[m].Fingerprint[:])
		return comp < 0
	})
	return l, h.MemberInfo[l:r]
}
