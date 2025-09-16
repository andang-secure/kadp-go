package cache

import (
	"context"
	logger "github.com/sirupsen/logrus"
	"sync"
	"time"
)

// KeyCacheEntry 密钥缓存条目
type KeyCacheEntry struct {
	Key        []byte
	CreatedAt  time.Time
	CancelFunc context.CancelFunc
}

// KeyCache 密钥缓存管理器
type keyCache struct {
	cache map[string]*KeyCacheEntry
	mutex sync.RWMutex
}

var KeyCache = &keyCache{
	cache: make(map[string]*KeyCacheEntry),
}

// Store 存储密钥到缓存，30分钟后自动删除
func (kc *keyCache) Store(label string, key []byte) {
	kc.mutex.Lock()
	defer kc.mutex.Unlock()

	// 如果已存在该标签的密钥，先取消之前的定时任务
	if entry, exists := kc.cache[label]; exists && entry.CancelFunc != nil {
		entry.CancelFunc()
		logger.Debugf("取消了标签 %s 的旧定时删除任务", label)
	}

	// 创建新的上下文和取消函数
	ctx, cancel := context.WithCancel(context.Background())

	// 创建缓存条目
	entry := &KeyCacheEntry{
		Key:        key,
		CreatedAt:  time.Now(),
		CancelFunc: cancel,
	}

	// 存储到缓存
	kc.cache[label] = entry

	// 启动30分钟后的自动删除任务
	go func() {
		timer := time.NewTimer(30 * time.Minute)
		defer timer.Stop()

		select {
		case <-timer.C:
			// 时间到了，删除密钥
			kc.mutex.Lock()
			delete(kc.cache, label)
			kc.mutex.Unlock()
			logger.Debugf("密钥缓存已过期并删除: %s", label)
		case <-ctx.Done():
			// 任务被取消
			logger.Debugf("密钥缓存删除任务被取消: %s", label)
		}
	}()

	logger.Debugf("密钥已缓存: %s，将在30分钟后自动删除", label)
}

// Retrieve 从缓存中获取密钥
func (kc *keyCache) Retrieve(label string) ([]byte, bool) {
	kc.mutex.RLock()
	defer kc.mutex.RUnlock()

	entry, exists := kc.cache[label]
	if !exists {
		return nil, false
	}

	// 检查是否过期（虽然有定时器，但双重检查更安全）
	if time.Since(entry.CreatedAt) > 30*time.Minute {
		return nil, false
	}

	return entry.Key, true
}

// Delete 立即删除缓存中的密钥
func (kc *keyCache) Delete(label string) {
	kc.mutex.Lock()
	defer kc.mutex.Unlock()

	if entry, exists := kc.cache[label]; exists {
		if entry.CancelFunc != nil {
			entry.CancelFunc()
		}
		delete(kc.cache, label)
		logger.Debugf("密钥缓存已删除: %s", label)
	}
}

// ListKeys 列出所有缓存的密钥标签（用于调试）
func (kc *keyCache) ListKeys() []string {
	kc.mutex.RLock()
	defer kc.mutex.RUnlock()

	keys := make([]string, 0, len(kc.cache))
	for key := range kc.cache {
		keys = append(keys, key)
	}
	return keys
}
