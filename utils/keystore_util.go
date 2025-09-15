package utils

import (
	"context"
	"fmt"
	"github.com/andang-secure/kadp-go/configs"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	logger "github.com/sirupsen/logrus"
	"log"
	"os"
	"sync"
	"time"
)

type KeyStoreObj struct {
	cachingKeyStore *keystore.KeyStore
}

func NewKeyStoreObj() *KeyStoreObj {
	return &KeyStoreObj{}
}

func (k *KeyStoreObj) init() {

	ks := keystore.New()

	if _, err := os.Stat(configs.KeystoreFileName); os.IsNotExist(err) {
		// 文件不存在，则创建新的 KeyStore 并保存到文件
		CreateKeyStore(ks)
	}

	f, err := os.Open(configs.KeystoreFileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if err = ks.Load(f, []byte(configs.KeystorePassword)); err != nil {
		panic(err)
	}
	k.cachingKeyStore = &ks
}

func (k *KeyStoreObj) StoreSecretKey(alias string, keyEntry keystore.PrivateKeyEntry) error {
	if k.cachingKeyStore == nil {
		k.init()
	}
	f, err := os.Create(configs.KeystoreFileName)
	if err != nil {
		return fmt.Errorf("failed to create keystore file: %v", err)
	}

	defer f.Close()

	err = k.cachingKeyStore.SetPrivateKeyEntry(alias, keyEntry, []byte(configs.KEY))
	if err != nil {
		return fmt.Errorf("failed to store key entry: %v", err)
	}

	err = k.cachingKeyStore.Store(f, []byte(configs.KeystorePassword))

	if err != nil {
		return fmt.Errorf("failed to store keystore: %v", err)
	}
	taskManager := NewTaskManager()
	taskManager.ScheduleDeletionWithContext(k.cachingKeyStore, alias)
	return err
}

func (k *KeyStoreObj) deleteSecretKey(alias string) {

	k.cachingKeyStore.DeleteEntry(alias)
}

func (k *KeyStoreObj) RetrieveSecretKey(label string) ([]byte, error) {
	if k.cachingKeyStore == nil {
		k.init()
	}

	keyEntry, err := k.cachingKeyStore.GetPrivateKeyEntry(label, []byte(configs.KEY))
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key entry: %v", err)
	}
	logger.Debug("key length:", len(keyEntry.PrivateKey))

	return keyEntry.PrivateKey, nil
}

type TaskManager struct {
	tasks map[string]context.CancelFunc
	mutex sync.RWMutex
}

func NewTaskManager() *TaskManager {
	return &TaskManager{
		tasks: make(map[string]context.CancelFunc),
	}
}

// ScheduleDeletionWithContext 安排删除任务
func (tm *TaskManager) ScheduleDeletionWithContext(cachingKeyStore *keystore.KeyStore, alias string) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// 取消已存在的任务
	if cancel, exists := tm.tasks[alias]; exists {
		cancel() // 取消之前的任务
		log.Printf("Cancelled previous deletion task for: %s", alias)
	}

	// 创建新的上下文
	ctx, cancel := context.WithCancel(context.Background())
	tm.tasks[alias] = cancel

	// 启动新的任务
	go func() {
		defer func() {
			// 任务完成后从管理器中移除
			tm.mutex.Lock()
			defer tm.mutex.Unlock()
			delete(tm.tasks, alias)
		}()

		timer := time.NewTimer(30 * time.Minute)
		defer timer.Stop()

		select {
		case <-timer.C:
			cachingKeyStore.DeleteEntry(alias)
			log.Printf("Deleted entry: %s", alias)
		case <-ctx.Done():
			log.Printf("Deletion task for %s was cancelled", alias)
		}
	}()

	log.Printf("Scheduled deletion task for: %s", alias)
}

// CancelDeletion 取消指定的删除任务
func (tm *TaskManager) CancelDeletion(alias string) bool {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if cancel, exists := tm.tasks[alias]; exists {
		cancel()
		delete(tm.tasks, alias)
		return true
	}
	return false
}
