package utils

import (
	"fmt"
	"github.com/go-irain/logger"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"log"
	"os"
	"time"
)

func ReadKeyStore(filename string, password []byte) keystore.KeyStore {

	ks := keystore.New()

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		// 文件不存在，则创建新的 KeyStore 并保存到文件
		CreateKeyStore(ks, filename, password)
		logger.Debug("keystore判定不存在,开始创建keystore文件")
	}

	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if err = ks.Load(f, password); err != nil {
		log.Fatal(err)
	}
	return ks
}

func CreateKeyStore(ks keystore.KeyStore, filename string, password []byte) {
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
	entry := keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       key,
		CertificateChain: nil,
	}
	return entry
}

func Zeroing(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func StoreSecretKey(alias string, keyEntry keystore.PrivateKeyEntry, ks keystore.KeyStore, filename string, password []byte) {
	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()
	err = ks.SetPrivateKeyEntry(alias, keyEntry, []byte("shanghaiandanggongsi"))
	if err != nil {
		fmt.Println(err)
	}

	err = ks.Store(f, password)

	if err != nil {
		log.Fatal(err) //nolint: gocritic
	}
}
