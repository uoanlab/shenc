package usecase

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/uoanlab/shenc/domain"
	"github.com/uoanlab/shenc/keys"
)

type App struct {
	Store *KeyStore
}

var ErrUnknownUser = fmt.Errorf("unknown user")

func (a *App) parseMembers(members []string) ([]domain.UserInfo, error) {
	ret := []domain.UserInfo{}
	for _, v := range members {
		param := strings.SplitN(v, ":", 2)
		if param[0] == "" {
			continue
		}
		ui := domain.UserInfo{}
		name := param[0]
		if len(param) > 1 {
			perm := param[1]
			if perm == "r" {
				ui.Permission = domain.PermRead
			} else if perm == "w" {
				ui.Permission = domain.PermWrite
			} else if perm == "rw" {
				ui.Permission = domain.PermFull
			} else {
				return nil, fmt.Errorf("invalid permission:%s", perm)
			}
		}
		pubkey, err := a.Store.GetByName(name)
		if err != nil {
			return nil, err
		}
		if pubkey == nil {
			return nil, fmt.Errorf("invalid member name:%s", name)
		}
		ui.PublicKey = pubkey
		pubkeyfp := pubkey.Fingerprint()
		copy(ui.Fingerprint[:], pubkeyfp[:12])

		ret = append(ret, ui)
	}
	return ret, nil
}

func (a *App) EncryptFile(in, out string, members []string) {
	_, inname := path.Split(in)
	if out == "" {
		out = inname + ".she"
	}
	keylistname := strings.TrimSuffix(out, path.Ext(out)) + ".keylist"

	fmt.Printf("Encrypting file...\n")

	// Construct header
	d, err := domain.NewData()
	if err != nil {
		fmt.Printf("Error occoured when encrypt file:\n%v\n", err)
		os.Exit(1)
	}

	// Prepare keylist
	_, err = os.Stat(keylistname)
	if err == nil {
		fmt.Printf("File is already exist. stop.\n")
		os.Exit(1)
	}
	cinfo, minfo, err := a.GenerateFileKey(keylistname, d.Header.UUID, members)
	if err != nil {
		fmt.Printf("Error occoured when generating file key:\n%v\n", err)
		os.Exit(1)
	}

	pubkeyfp := cinfo.PublicKey.Fingerprint()
	d.Header.OwnerInfo = cinfo

	d.Header.MemberInfo = minfo
	if err != nil {
		fmt.Printf("Error occoured when encrypt file:\n%v\n", err)
		os.Exit(1)
	}
	d.Header.Sort()

	// privkey, err := a.Store.GetMyPrivateKey()
	fileid := fmt.Sprintf("%X", d.Header.UUID)
	ownerfp := fmt.Sprintf("%X", cinfo.PublicKey.Fingerprint())
	privkey, err := a.Store.GetFileKey(fileid, ownerfp)
	if err != nil {
		fmt.Printf("Error occoured when encrypt file:\n%v\n", err)
		os.Exit(1)
	}

	// Sign header
	_, err = d.Header.SignAndMarshal(privkey)
	if err != nil {
		fmt.Printf("Error occoured when encrypt file:\n%v\n", err)
		os.Exit(1)
	}

	f, err := os.Open(in)
	if err != nil {
		fmt.Printf("Error occoured when encrypt file:\n%v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	err = d.RotateShKey()
	if err != nil {
		fmt.Printf("Error occoured when encrypt file:\n%v\n", err)
		os.Exit(1)
	}
	d.UpdateTime = d.Header.CreateTime
	copy(d.UpdaterFingerprint[:], pubkeyfp)

	d.FileName = inname
	d.OrgFilePath = in

	_, err = os.Stat(out)
	if err == nil {
		fmt.Printf("File is already exist. stop.\n")
		os.Exit(1)
	}
	outfile, err := os.Create(out)
	if err != nil {
		fmt.Printf("Error occoured when encrypt file:\n%v\n", err)
		os.Exit(1)
	}
	defer outfile.Close()

	err = d.SignAndMarshal(privkey, outfile)
	if err != nil {
		fmt.Printf("Error occoured when encrypt file:\n%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Encrypt file success.\n")

	if env := os.Getenv("SHENCNOCOPY"); env != "1" {
		fmt.Printf("Copying encrypt file...\n")
		_, err = outfile.Seek(0, 0)
		if err != nil {
			fmt.Printf("Error occoured when copying file:\n%v\n", err)
			os.Exit(1)
		}

		fileidstr := fmt.Sprintf("%X", d.Header.UUID)
		ownfpstr := fmt.Sprintf("%X", cinfo.PublicKey.Fingerprint())
		hashstr := fmt.Sprintf("%X", d.Hash)
		filed := path.Join(a.Store.Filed, fileidstr, ownfpstr, hashstr)
		fcp, err := os.Create(filed)
		if err != nil {
			fmt.Printf("Error occoured when copying file:\n%v\n", err)
			os.Exit(1)
		}
		defer fcp.Close()
		_, err = io.Copy(fcp, outfile)
		if err != nil {
			fmt.Printf("Error occoured when copying file:\n%v\n", err)
			os.Exit(1)
		}
	}
}

func (a *App) DecryptFile(in, out string) {
	fmt.Printf("Decrypting file...\n")
	if out == "" {
		out = path.Dir(in)
	}
	f, err := os.Open(in)
	if err != nil {
		fmt.Printf("Error occoured when decrypt file:\n%v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// Load file key
	findPrivkey := func(fileid, ownerid string) keys.PrivateKey {
		key, err := a.Store.GetFileKey(fileid, ownerid)
		if err != nil {
			return nil
		}
		return key
	}
	d := domain.Data{}
	err = d.UnmarshalAndVerify(f, out, findPrivkey)
	if err != nil {
		fmt.Printf("Error occoured when decrypt file:\n%v\n", err)
		os.Exit(1)
	}

	ownfp := d.Header.OwnerInfo.PublicKey.Fingerprint()
	ownfpstr := fmt.Sprintf("%X", ownfp)

	// Owner is already known by getting key list

	// mypub, err := a.Store.GetMyPublicKey()
	// if err != nil {
	// 	fmt.Printf("Error occoured when decrypt file:\n%v\n", err)
	// 	os.Exit(1)
	// }
	// // Check owner is not me
	// if !bytes.Equal(ownfp, mypub.Fingerprint()) {
	// 	// Check known user or not
	// 	ownpub, err := a.Store.GetByFingerprint(ownfpstr)
	// 	if err != nil {
	// 		fmt.Printf("Error occoured when decrypt file:\n%v\n", err)
	// 		os.Exit(1)
	// 	}
	// 	if ownpub == nil {
	// 		fmt.Printf("Error occoured when decrypt file:\n%v\n", ErrUnknownUser)
	// 		os.Exit(1)
	// 	}
	// 	// Owner is known user
	// }
	fmt.Printf("Decrypt file success.\n")
	if env := os.Getenv("SHENCNOCOPY"); env != "1" {
		fmt.Printf("Copying encrypt file...\n")
		_, err = f.Seek(0, 0)
		if err != nil {
			fmt.Printf("Error occoured when copying file:\n%v\n", err)
			os.Exit(1)
		}
		fileidstr := fmt.Sprintf("%X", d.Header.UUID)
		hashstr := fmt.Sprintf("%X", d.Hash)
		filed := path.Join(a.Store.Filed, fileidstr, ownfpstr, hashstr)
		fcp, err := os.Create(filed)
		if err != nil {
			fmt.Printf("Error occoured when copying file:\n%v\n", err)
			os.Exit(1)
		}
		defer fcp.Close()
		_, err = io.Copy(fcp, f)
		if err != nil {
			fmt.Printf("Error occoured when copying file:\n%v\n", err)
			os.Exit(1)
		}
	}
}

func (a *App) AddKeyList(in string) {
	// Load key list file
	klraw, err := ioutil.ReadFile(in)
	if err != nil {
		fmt.Printf("Error occoured when read key file:\n%v\n", err)
		os.Exit(1)
	}

	kl, err := domain.UnmarshalKeyListFile(klraw)
	if err != nil {
		fmt.Printf("Error occoured when unmarshal key list file:\n%v\n", err)
		os.Exit(1)
	}

	// Verify owner
	ownfpstr := fmt.Sprintf("%X", kl.Creator.Fingerprint)

	cpubkey, err := a.Store.GetMyPublicKey()
	if err != nil {
		fmt.Printf("Error occoured when add key list:\n%v\n", err)
		os.Exit(1)
	}
	// Check owner is not me
	if !bytes.Equal(kl.Creator.Fingerprint[:], cpubkey.Fingerprint()) {
		cpubkey, err = a.Store.GetByFingerprint(ownfpstr)
		if err != nil {
			fmt.Printf("Error occoured when get public key:\n%v\n", err)
			os.Exit(1)
		}
		if cpubkey == nil {
			fmt.Printf("Error occoured when add key list file:\n%v\n", ErrUnknownUser)
			os.Exit(1)
		}
	}

	err = kl.Verify(cpubkey)
	if err != nil {
		fmt.Printf("Error occoured when verify key list file:\n%v\n", err)
		os.Exit(1)
	}

	// Add key list into store
	err = a.Store.AddFileKey(kl)
	if err != nil {
		fmt.Printf("Error occoured when add key list file:\n%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Registered key list file. (FileID: %X)\n", kl.FileID)
}

func (a *App) UpdateFile(base, in, out string) {
	fmt.Printf("Loading ShEnc file...\n")

	fbase, err := os.Open(base)
	if err != nil {
		fmt.Printf("Error occoured when update file:\n%v\n", err)
		os.Exit(1)
	}
	defer fbase.Close()

	privkey, err := a.Store.GetMyPrivateKey()
	if err != nil {
		fmt.Printf("Error occoured when update file:\n%v\n", err)
		os.Exit(1)
	}
	findPrivkey := func(fileid, ownerid string) keys.PrivateKey {
		key, err := a.Store.GetFileKey(fileid, ownerid)
		if err != nil {
			return nil
		}
		return key
	}
	d := domain.Data{}
	err = d.UnmarshalAndVerify(fbase, "", findPrivkey)
	if err != nil {
		fmt.Printf("Error occoured when update file:\n%v\n", err)
		os.Exit(1)
	}
	ownfp := d.Header.OwnerInfo.PublicKey.Fingerprint()
	ownfpstr := fmt.Sprintf("%X", ownfp)

	mypub, err := a.Store.GetMyPublicKey()
	if err != nil {
		fmt.Printf("Error occoured when update file:\n%v\n", err)
		os.Exit(1)
	}
	// Check owner is not me
	if !bytes.Equal(ownfp, mypub.Fingerprint()) {
		// Check known user or not
		ownpub, err := a.Store.GetByFingerprint(ownfpstr)
		if err != nil {
			fmt.Printf("Error occoured when update file:\n%v\n", err)
			os.Exit(1)
		}
		if ownpub == nil {
			fmt.Printf("Error occoured when update file:\n%v\n", ErrUnknownUser)
			os.Exit(1)
		}
		// Owner is known user
	}

	fmt.Printf("Updating file...\n")

	fin, err := os.Open(in)
	if err != nil {
		fmt.Printf("Error occoured when update file:\n%v\n", err)
		os.Exit(1)
	}
	defer fin.Close()

	err = d.RotateShKey()
	if err != nil {
		fmt.Printf("Error occoured when update file:\n%v\n", err)
		os.Exit(1)
	}
	copy(d.PreviousFileHash[:], d.Hash[:])
	d.UpdateTime = time.Now()
	pubkey, err := a.Store.GetMyPublicKey()
	if err != nil {
		fmt.Printf("Error occoured when update file:\n%v\n", err)
		os.Exit(1)
	}
	pubkeyfp := pubkey.Fingerprint()
	copy(d.UpdaterFingerprint[:], pubkeyfp)

	_, inname := path.Split(in)
	d.FileName = inname
	d.OrgFilePath = in

	if out == "" {
		out = inname + ".she"
	}
	_, err = os.Stat(out)
	if err == nil {
		fmt.Printf("File is already exist. stop.\n")
		os.Exit(1)
	}
	outfile, err := os.Create(out)
	if err != nil {
		fmt.Printf("Error occoured when update file:\n%v\n", err)
		os.Exit(1)
	}

	err = d.SignAndMarshal(privkey, outfile)
	if err != nil {
		fmt.Printf("Error occoured when update file:\n%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Update file success.\n")
	fmt.Printf("Copying encrypt file...\n")
	_, err = outfile.Seek(0, 0)
	if err != nil {
		fmt.Printf("Error occoured when copying file:\n%v\n", err)
		os.Exit(1)
	}
	fileidstr := fmt.Sprintf("%X", d.Header.UUID)
	hashstr := fmt.Sprintf("%X", d.Hash)
	filed := path.Join(a.Store.Filed, fileidstr, ownfpstr, hashstr)
	fcp, err := os.Create(filed)
	if err != nil {
		fmt.Printf("Error occoured when copying file:\n%v\n", err)
		os.Exit(1)
	}
	defer fcp.Close()
	_, err = io.Copy(fcp, outfile)
	if err != nil {
		fmt.Printf("Error occoured when copying file:\n%v\n", err)
		os.Exit(1)
	}
}

func (a *App) ShowFileInfo(in string) {
	fmt.Printf("Loading ShEnc file...\n")

	fbase, err := os.Open(in)
	if err != nil {
		fmt.Printf("Error occoured when loading file:\n%v\n", err)
		os.Exit(1)
	}
	defer fbase.Close()

	findPrivkey := func(fileid, ownerid string) keys.PrivateKey {
		key, err := a.Store.GetFileKey(fileid, ownerid)
		if err != nil {
			return nil
		}
		return key
	}
	d := domain.Data{}
	err = d.UnmarshalAndVerify(fbase, "", findPrivkey)
	if err != nil {
		fmt.Printf("Error occoured when loading file:\n%v\n", err)
		os.Exit(1)
	}

	// TODO: Show file info
	// Show creator and creation time

	ownfp := d.Header.OwnerInfo.PublicKey.Fingerprint()
	ownfpstr := fmt.Sprintf("%X", ownfp)

	cname := a.Store.GetNameByFingerprint(ownfpstr)

	if cname == "" {
		mypub, err := a.Store.GetMyPublicKey()
		if err != nil {
			fmt.Printf("Error occoured when loading file:\n%v\n", err)
			os.Exit(1)
		}
		if bytes.Equal(ownfp, mypub.Fingerprint()) {
			cname = "you"
		} else {
			cname = "unknown"
		}
	} else {
		cname = "\"" + cname + "\""
	}

	fmt.Printf("Created by %s at %v (signed at %v)\n", cname, d.Header.CreateTime, d.Header.SignTime)

	// Show updater and update time
	updaterfp := d.UpdaterFingerprint[:]
	updaterfpstr := fmt.Sprintf("%X", updaterfp)

	uname := a.Store.GetNameByFingerprint(updaterfpstr)

	if uname == "" {
		mypub, err := a.Store.GetMyPublicKey()
		if err != nil {
			fmt.Printf("Error occoured when loading file:\n%v\n", err)
			os.Exit(1)
		}
		if bytes.Equal(updaterfp, mypub.Fingerprint()) {
			uname = "you"
		} else {
			uname = "unknown"
		}
	} else {
		uname = "\"" + uname + "\""
	}

	fmt.Printf("Updated by %s at %v\n", uname, d.UpdateTime)

	// Show members' info
	fmt.Printf("\n")
	fmt.Printf("%d members:\n", len(d.Header.MemberInfo))
	for _, m := range d.Header.MemberInfo {
		mfp := m.PublicKey.Fingerprint()
		mfpstr := fmt.Sprintf("%X", mfp)
		mname := a.Store.GetNameByFingerprint(mfpstr)
		if mname == "" {
			mypub, err := a.Store.GetMyPublicKey()
			if err != nil {
				fmt.Printf("Error occoured when loading file:\n%v\n", err)
				os.Exit(1)
			}
			if bytes.Equal(updaterfp, mypub.Fingerprint()) {
				uname = "you"
			} else {
				uname = "unknown"
			}
		} else {
			mname = "\"" + mname + "\""
		}
		permstr := ""
		if m.Permission&domain.PermRead != 0 {
			permstr += "r"
		}
		if m.Permission&domain.PermWrite != 0 {
			permstr += "w"
		}
		fmt.Printf("%s(%s...): %s\n", mname, mfpstr[:32], permstr)
	}

}

func (a *App) ListPublicKeys() {
	for fp, name := range a.Store.keyList {
		fmt.Printf("%s:%s\n", name, fp)
	}
}

func (a *App) AddPublicKey(in, name string) {
	re := regexp.MustCompile(`[^A-Za-z0-9._@]`)
	if re.MatchString(name) {
		fmt.Printf("The charactor in name \"%s\" cannot be used.\n", name)
		os.Exit(1)
	}
	pubkey, err := keys.LoadPublicKeyFromFile(in)
	if err != nil {
		fmt.Printf("Error occoured when adding public key:\n%v\n", err)
		os.Exit(1)
	}
	fpstr := fmt.Sprintf("%X", pubkey.Fingerprint())
	pubkeys, err := a.Store.GetByFingerprint(fpstr)
	if err != nil {
		fmt.Printf("Error occoured when adding public key:\n%v\n", err)
		os.Exit(1)
	}
	if pubkeys != nil {
		fmt.Printf("The public key is already exist.\n")
		os.Exit(1)
	}
	fmt.Printf("Adding public key: %s\n", name)
	fmt.Printf("Fingerprint: %s\n", fpstr)
	fmt.Printf("Do you continue?[y/n] ")
	ans := ""
	_, err = fmt.Scan(&ans)
	if err != nil {
		os.Exit(1)
	}
	ans = strings.ToUpper(ans)
	if ans != "Y" && ans != "YES" {
		os.Exit(1)
	}
	err = a.Store.AddPublicKey(pubkey, name)
	if err != nil {
		fmt.Printf("Error occoured when adding public key:\n%v\n", err)
		os.Exit(1)
	}
}

func (a *App) RemovePublicKey(name string) {
	pubkey, err := a.Store.GetByName(name)
	if err != nil {
		fmt.Printf("Error occoured when removing public key:\n%v\n", err)
		os.Exit(1)
	}
	if pubkey == nil {
		fmt.Printf("The public key is not exist.\n")
		os.Exit(1)
	}
	fpstr := fmt.Sprintf("%X", pubkey.Fingerprint())
	fmt.Printf("Removing public key: %s\n", name)
	fmt.Printf("Fingerprint: %s\n", fpstr)
	fmt.Printf("Do you continue?[y/n] ")
	ans := ""
	_, err = fmt.Scan(&ans)
	if err != nil {
		os.Exit(1)
	}
	ans = strings.ToUpper(ans)
	if ans != "Y" && ans != "YES" {
		os.Exit(1)
	}
	err = a.Store.RemovePublicKey(fpstr)
	if err != nil {
		fmt.Printf("Error occoured when removing public key:\n%v\n", err)
		os.Exit(1)
	}
}

func IsShEncFile(in string) (bool, error) {
	f, err := os.Open(in)
	if err != nil {
		return false, err
	}
	defer f.Close()

	buf := make([]byte, 8)
	n, err := f.Read(buf)
	if err != nil {
		return false, err
	}
	if n < 8 {
		return false, nil
	}
	if !bytes.Equal(buf[:6], domain.MagicCode[:]) {
		return false, nil
	}
	return true, nil
}

func (a *App) GenerateFileKey(out string, fileID [16]byte, members []string) (domain.UserInfo, []domain.UserInfo, error) {
	keyencfunc := func(pubkey keys.PublicKey, dat []byte) ([]byte, error) {
		res := []byte{}
		const sizeKey = 32
		const sizeIV = aes.BlockSize

		// Generate enckey
		key := make([]byte, sizeKey)
		for {
			_, err := rand.Read(key)
			if err != nil {
				return nil, err
			}
			if key[0] != 0 {
				break
			}
		}

		iv := make([]byte, sizeIV)
		for {
			_, err := rand.Read(iv)
			if err != nil {
				return nil, err
			}
			if iv[0] != 0 {
				break
			}
		}

		// Encrypt enckey with pubkey
		keyiv := append(key, iv...)
		enckey, err := pubkey.Encrypt(keyiv)
		if err != nil {
			return nil, err
		}

		buf := make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, uint16(len(enckey)))
		res = append(res, buf...)
		res = append(res, enckey...)

		// Encrypt data with enckey
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		blkmd := cipher.NewCBCEncrypter(blk, iv)
		ebs := blkmd.BlockSize()

		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, uint16(len(dat)))
		res = append(res, buf...)

		// Padding
		if len(dat)%ebs != 0 {
			buf = make([]byte, ebs-(len(dat)%ebs))
			rand.Read(buf)
			dat = append(dat, buf...)
		}

		blkmd.CryptBlocks(dat, dat)

		res = append(res, dat...)

		return res, nil
	}
	cinfo := domain.UserInfo{}
	minfo := []domain.UserInfo{}

	keylist := domain.KeyListFile{
		Version:    1,
		FileID:     fileID,
		UpdateTime: time.Now(),
		Creator:    domain.KeyListUserInfo{},
		Members:    []domain.KeyListUserInfo{},
	}

	fmt.Printf("Generating file key...\n")

	// Generate creator's key
	fileprivkey, err := keys.GenerateECCKey()
	if err != nil {
		return cinfo, minfo, err
	}
	filepubkey := fileprivkey.Public()
	cinfo.Permission = domain.PermOwner
	cinfo.PublicKey = filepubkey
	pubkeyfp := filepubkey.Fingerprint()
	copy(cinfo.Fingerprint[:], pubkeyfp[:12])

	// Set creator's key
	// Fingerprint
	pubkey, err := a.Store.GetMyPublicKey()
	if err != nil {
		return cinfo, minfo, err
	}
	copy(keylist.Creator.Fingerprint[:], pubkey.Fingerprint())
	// File key fingerprint
	copy(keylist.Creator.FileKeyFingerprint[:], filepubkey.Fingerprint())
	// File key
	fileprivkeyraw, err := fileprivkey.Marshal()
	if err != nil {
		return cinfo, minfo, err
	}
	encfileprivkey, err := keyencfunc(pubkey, fileprivkeyraw) //pubkey.Encrypt(fileprivkeyraw)
	if err != nil {
		return cinfo, minfo, err
	}
	keylist.Creator.EncryptedFileKey = encfileprivkey

	meminfo, err := a.parseMembers(members)
	if err != nil {
		return cinfo, minfo, err
	}

	// Generate and set members' keys
	for _, m := range meminfo {
		mkinfo := domain.KeyListUserInfo{}
		mi := domain.UserInfo{}
		// Generate key
		fileprivkey, err = keys.GenerateECCKey()
		if err != nil {
			return cinfo, minfo, err
		}
		filepubkey = fileprivkey.Public()
		mi.Permission = m.Permission
		mi.PublicKey = filepubkey
		pubkeyfp := filepubkey.Fingerprint()
		copy(mi.Fingerprint[:], pubkeyfp[:12])
		minfo = append(minfo, mi)

		// Fingerprint
		copy(mkinfo.Fingerprint[:], m.PublicKey.Fingerprint())
		// File key fingerprint
		copy(mkinfo.FileKeyFingerprint[:], filepubkey.Fingerprint())
		// File key
		fileprivkeyraw, err := fileprivkey.Marshal()
		if err != nil {
			return cinfo, minfo, err
		}
		encfileprivkey, err := keyencfunc(m.PublicKey, fileprivkeyraw) // m.PublicKey.Encrypt(fileprivkeyraw)
		if err != nil {
			return cinfo, minfo, err
		}
		mkinfo.EncryptedFileKey = encfileprivkey

		keylist.Members = append(keylist.Members, mkinfo)
	}

	// Sign
	privkey, err := a.Store.GetMyPrivateKey()
	if err != nil {
		return cinfo, minfo, err
	}
	err = keylist.Sign(privkey)
	if err != nil {
		return cinfo, minfo, err
	}

	// Store local key list
	err = a.Store.AddFileKey(keylist)
	if err != nil {
		return cinfo, minfo, err
	}

	keylistraw, err := keylist.Marshal()
	if err != nil {
		return cinfo, minfo, err
	}
	err = ioutil.WriteFile(out, keylistraw, 0644)
	if err != nil {
		return cinfo, minfo, err
	}
	return cinfo, minfo, nil
}
