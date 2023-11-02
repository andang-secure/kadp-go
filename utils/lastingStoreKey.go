package utils

import (
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"log"
	"os"
)

func ReadKeyStore(filename string, password []byte) keystore.KeyStore {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		// 文件不存在，则创建新的 KeyStore 并保存到文件
		ks := keystore.New()
		WriteKeyStore(ks, filename, password)
		return ks
	}

	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	ks := keystore.New()
	if err := ks.Load(f, password); err != nil {
		log.Fatal(err)
	}

	return ks
}

func WriteKeyStore(ks keystore.KeyStore, filename string, password []byte) {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	err = ks.Store(f, password)
	if err != nil {
		log.Fatal(err) //nolint: gocritic
	}
}

//
//func ReadKeyStore(filename string, password []byte) keystore.KeyStore {
//	f, err := os.Open(filename)
//	ks := keystore.New()
//
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	defer func() {
//		if err := f.Close(); err != nil {
//			log.Fatal(err)
//		}
//	}()
//
//	if err := ks.Load(f, password); err != nil {
//		log.Fatal(err) //nolint: gocritic
//	}
//
//	return ks
//}

func CreateKeyEntry(key []byte) keystore.PrivateKeyEntry {
	entry := keystore.PrivateKeyEntry{PrivateKey: key}
	return entry
}

func Zeroing(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
