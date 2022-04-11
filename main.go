package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/uoanlab/shenc/keys"
	"github.com/uoanlab/shenc/usecase"
)

const (
	AppVersion = "2.1.0"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "keygentest" {
		if os.Args[2] == "ecc" {
			fmt.Println("Key generation test for ECC")
			start := time.Now()
			for i := 0; i < 10; i++ {
				_, err := keys.GenerateECCKey()
				if err != nil {
					fmt.Printf("Error occoured when generate key:\n%v\n", err)
					os.Exit(1)
				}
			}
			end := time.Now()
			fmt.Printf("Time elapsed: %v\n", end.Sub(start))
		} else if os.Args[2] == "rsa" {
			fmt.Println("Key generation test for RSA")
			start := time.Now()
			for i := 0; i < 10; i++ {
				_, err := keys.GenerateRSAKey()
				if err != nil {
					fmt.Printf("Error occoured when generate key:\n%v\n", err)
					os.Exit(1)
				}
			}
			end := time.Now()
			fmt.Printf("Time elapsed: %v\n", end.Sub(start))
		}
		return
	}

	if len(os.Args) == 3 && os.Args[1] == "ecctest" {
		var priv keys.PrivateKey
		if os.Args[2] == "384" {
			fmt.Println("ECC test for P384")
			var err error
			priv, err = keys.GenerateECC384Key()
			if err != nil {
				fmt.Printf("Error occoured when generate key:\n%v\n", err)
				os.Exit(1)
			}
		} else if os.Args[2] == "521" {
			fmt.Println("ECC test for P521")
			var err error
			priv, err = keys.GenerateECCKey()
			if err != nil {
				fmt.Printf("Error occoured when generate key:\n%v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Println("Invalid argument")
			os.Exit(1)
		}

		dat := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
		fmt.Printf("Original data: %s (%d bytes)\n", string(dat), len(dat))
		fmt.Println("Encryption")
		start := time.Now()
		for i := 0; i < 1000; i++ {
			_, err := priv.Public().Encrypt(dat)
			if err != nil {
				fmt.Printf("Error occoured when generate key:\n%v\n", err)
				os.Exit(1)
			}
		}
		end := time.Now()
		fmt.Printf("Encryption time: %v\n", end.Sub(start))

		encdat, err := priv.Public().Encrypt(dat)
		if err != nil {
			fmt.Printf("Error occoured when generate key:\n%v\n", err)
			os.Exit(1)
		}

		start = time.Now()
		for i := 0; i < 1000; i++ {
			_, err := priv.Decrypt(encdat)
			if err != nil {
				fmt.Printf("Error occoured when generate key:\n%v\n", err)
				os.Exit(1)
			}
		}
		end = time.Now()
		fmt.Printf("Decryption time: %v\n", end.Sub(start))
		return
	}

	s, err := usecase.NewKeyStore()
	if err != nil {
		if err != usecase.ErrPrivateKeyNotFound {
			fmt.Printf("Error occoured when init:\n%v\n", err)
			os.Exit(1)
		}
		ans := ""
		fmt.Printf("Do you want to generate key file?(Y/n): ")
		_, err := fmt.Scan(&ans)
		if err != nil {
			os.Exit(1)
		}
		ans = strings.ToUpper(ans)
		if ans != "" && ans != "Y" && ans != "YES" {
			os.Exit(1)
		}

		// Generate keys
		privkey, err := keys.GenerateECCKey()
		if err != nil {
			fmt.Printf("Error occoured when generate key:\n%v\n", err)
			os.Exit(1)
		}
		err = keys.SavePrivateKeyToFile(s.Prvkeyf, privkey)
		if err != nil {
			fmt.Printf("Error occoured when generate key:\n%v\n", err)
			os.Exit(1)
		}
		pubkey := privkey.Public()
		err = keys.SavePublicKeyToFile(s.Pubkeyf, pubkey)
		if err != nil {
			fmt.Printf("Error occoured when generate key:\n%v\n", err)
			os.Exit(1)
		}

		fmt.Println("Initialization is finished.")
	}

	if len(os.Args) == 1 {
		showHelp()
		os.Exit(1)
	}
	a := usecase.App{Store: &s}
	switch os.Args[1] {
	case "help":
		showHelp()
		return
	case "version":
		showVer()
		return
	case "reg":
		if len(os.Args) == 3 {
			a.AddKeyList(os.Args[2])
		} else {
			showHelp()
			os.Exit(1)
		}
	case "enc":
		in := ""
		out := ""
		members := []string{}
		if len(os.Args) == 4 {
			in = os.Args[2]
			members = strings.Split(os.Args[3], ",")
		} else if len(os.Args) == 5 {
			in = os.Args[2]
			out = os.Args[3]
			members = strings.Split(os.Args[4], ",")
		} else {
			showHelp()
			os.Exit(1)
		}
		a.EncryptFile(in, out, members)
	case "dec":
		in := ""
		out := ""
		if len(os.Args) == 3 {
			in = os.Args[2]
		} else if len(os.Args) == 4 {
			in = os.Args[2]
			out = os.Args[3]
		} else if len(os.Args) == 5 {
			a.AddKeyList(os.Args[2])
			in = os.Args[3]
			out = os.Args[4]
		} else {
			showHelp()
			os.Exit(1)
		}
		a.DecryptFile(in, out)
	case "update":
		base := ""
		in := ""
		out := ""
		// members := []string{}
		if len(os.Args) == 4 {
			base = os.Args[2]
			in = os.Args[3]
		} else if len(os.Args) == 5 {
			// 	base = os.Args[2]
			// 	in = os.Args[3]
			// 	members = strings.Split(os.Args[4], ",")
			// } else if len(os.Args) == 6 {
			base = os.Args[2]
			in = os.Args[3]
			out = os.Args[4]
			// members = strings.Split(os.Args[5], ",")
		} else {
			showHelp()
			os.Exit(1)
		}
		// a.UpdateFile(base, in, out, members)
		a.UpdateFile(base, in, out)
	case "info":
		if len(os.Args) != 3 {
			showHelp()
			os.Exit(1)
		}
		in := os.Args[2]
		a.ShowFileInfo(in)
	case "pub":
		if len(os.Args) == 2 {
			showHelp()
			os.Exit(1)
		}
		switch os.Args[2] {
		case "list":
			a.ListPublicKeys()
		case "add":
			if len(os.Args) != 5 {
				showHelp()
				os.Exit(1)
			}
			in := os.Args[3]
			name := os.Args[4]
			a.AddPublicKey(in, name)
		case "remove":
			if len(os.Args) != 4 {
				showHelp()
				os.Exit(1)
			}
			in := os.Args[3]
			a.RemovePublicKey(in)
		}
	default:
		// Check if file or not
		fi, err := os.Stat(os.Args[1])
		if os.IsNotExist(err) {
			showHelp()
			os.Exit(1)
		}
		if err != nil {
			fmt.Printf("Error occoured when open file:\n%v\n", err)
			os.Exit(1)
		}
		if fi.IsDir() {
			showHelp()
			os.Exit(1)
		}
		// Check file type
		isshenc, err := usecase.IsShEncFile(os.Args[1])
		if err != nil {
			fmt.Printf("Error occoured when open file:\n%v\n", err)
			os.Exit(1)
		}
		if isshenc {
			// if ShEnc file: Decrypt
			out := ""
			if len(os.Args) == 3 {
				out = os.Args[2]
			}
			a.DecryptFile(os.Args[1], out)
		} else {
			// if normal file: Encrypt
			out := ""
			members := []string{}
			if len(os.Args) == 3 { // member list
				members = strings.Split(os.Args[2], ",")
			} else if len(os.Args) == 4 { // dest and member list
				out = os.Args[2]
				members = strings.Split(os.Args[3], ",")
			} else {
				showHelp()
				os.Exit(1)
			}
			a.EncryptFile(os.Args[1], out, members)
		}
	}
}

func showHelp() {
	os.Args[0] = "shenc"
	fmt.Printf("Usage: %s [help | version] \n", os.Args[0])
	fmt.Println("")
	fmt.Printf("       %s src [dst] member\n", os.Args[0])
	fmt.Printf("       %s reg keylist\n", os.Args[0])
	fmt.Printf("       %s enc src [dst] member\n", os.Args[0])
	fmt.Printf("       %s dec [keylist] src [dst]\n", os.Args[0])
	fmt.Printf("       %s update base src [dst]\n", os.Args[0])
	fmt.Printf("       %s info src\n", os.Args[0])
	fmt.Println("")
	fmt.Printf("       %s pub list\n", os.Args[0])
	fmt.Printf("       %s pub add pubkey name\n", os.Args[0])
	fmt.Printf("       %s pub remove name\n", os.Args[0])
	fmt.Println("")
	fmt.Println("Sub command")
	fmt.Println("help        Show help.")
	fmt.Println("version     Show version.")
	fmt.Println("reg         Register key list.")
	fmt.Println("enc         Encrypt src file and save to dst dir with member permission.")
	fmt.Println("dec         Decrypt src file and save to dst dir")
	fmt.Println("update      Update ShEnc file based on base file with src and save to dst dir.")
	fmt.Println("info        Show ShEnc file information.")
	fmt.Println("pub list    Show public key list already registered.")
	fmt.Println("pub add     Add public key to known list.")
	fmt.Println("pub remove  Remove public key from known list.")
	fmt.Println("")
}

func showVer() {
	fmt.Printf("ShEnc tool ver%s\n\n", AppVersion)
}
