package test

import (
	"crypto/rand"
	"fmt"
	"github.com/andang-secure/kadp-go/configs"
	"github.com/andang-secure/kadp-go/kadp"
	logger "github.com/sirupsen/logrus"
	"sync"
	"testing"
	"time"
)

func BenchmarkEncryptionSpeed(b *testing.B) {
	logger.SetLevel(logger.ErrorLevel) // 减少日志输出以避免影响测试结果

	// 初始化客户端
	url := "http://192.168.0.129:8190"
	RegisterToken := "hnludUczLOwZfj0t84j1Eh0btPVNviLgPSjOfuS8oKaNNLACoKUd56YNb31jzU+d"
	token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEMQiHkMEfcYVm5LCUFDACn/4uYJNqpgHbrttZD1lDkyDuKsYM0MixYY2ZkImWaSB72eZX0pGbMKoOk5e4nAvIRcHEcQc8Lk/BmHMBRmK10wsziUiedJJB5rDzTEy2cC1/+v5f2gsHfXNjEY0aJmvegzuD2PKC72TTofMnvzJz2abUUafgTjCRnGe3x4iTN5ZKUtx/89hfUahPcUD5H9hreRPVpFvEk/XV3yV3B3OhI2N1Lpops2R20qfdl/2VfKbhIklvHWEL1UoWmGUII6G4jOTr0FZoKOXwnlvasbTdkiFGgGI+EUgbgYh4+r8Z875ADNEF+Uwae1UWKHs7Brrf9pB/bvkrWJIr4q1bduMYMLb3sYjkjchlyfwd+5WIESIcAmQaB1V5ChLDSMOXudqAh9jnuibzNGkBjAcwMRTB+K0b5mTkwyXIJTUSIIHvco8IZLVoPWGrDX/nEamGuzqbGE="

	myClient, err := kadp.NewKADPClient(&configs.KmsConfig{
		Domain:           url,
		Credential:       token,
		RegisterToken:    RegisterToken,
		KeystoreFileName: "keystore1.jks",
		KeystorePassword: "123456",
	})
	if err != nil {
		b.Fatal(err)
	}

	// 创建密钥
	label := "benchmark-key"
	key, err := myClient.CreateCipherKey(32, label, 1)
	if err != nil {
		b.Fatal(err)
	}

	// 生成测试数据
	testData := make([]byte, 1024) // 1KB 数据
	_, err = rand.Read(testData)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("AES-ECB-NoPadding", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := myClient.Encipher(&kadp.EncipherRequest{
				Plaintext: testData,
				CipherKey: key,
				Algorithm: kadp.AES,
				Mode:      kadp.ECB,
				Padding:   kadp.NoPadding,
				Label:     label,
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("AES-CBC-PKCS5Padding", func(b *testing.B) {
		iv := make([]byte, 16)
		_, err = rand.Read(iv)
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := myClient.Encipher(&kadp.EncipherRequest{
				Plaintext: testData,
				CipherKey: key,
				Algorithm: kadp.AES,
				Mode:      kadp.CBC,
				Padding:   kadp.PKCS5Padding,
				Label:     label,
				IV:        string(iv),
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("FPE-FF1", func(b *testing.B) {
		plaintext := "1234567890123456"
		tweak := "123456"
		alphabet := "0123456789"

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := myClient.FpeEncipher(&kadp.FpeEncipherRequest{
				Plaintext: plaintext,
				CipherKey: key,
				Fpe:       kadp.FF1,
				Tweak:     tweak,
				Alphabet:  alphabet,
				Label:     label,
				Start:     0,
				End:       10,
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("SM2-Asymmetric-Encryption", func(b *testing.B) {
		// 生成密钥对
		pub, _, err := myClient.AsymmetricKeyPair(kadp.SM2)
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := myClient.AsymmetricEncrypt(&kadp.AsymmetricEncryptRequest{
				Plaintext: string(testData[:64]), // SM2 对数据长度有限制
				Algorithm: kadp.SM2,
				PublicKey: pub,
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("HMAC-SHA256", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := myClient.Hmac(&kadp.HmacRequest{
				CipherKey: key,
				Message:   testData,
				Label:     label,
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// 并发加密测试
func BenchmarkConcurrentEncryption(b *testing.B) {
	logger.SetLevel(logger.ErrorLevel)

	url := "http://192.168.0.129:8190"
	RegisterToken := "hnludUczLOwZfj0t84j1Eh0btPVNviLgPSjOfuS8oKaNNLACoKUd56YNb31jzU+d"
	token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEMQiHkMEfcYVm5LCUFDACn/4uYJNqpgHbrttZD1lDkyDuKsYM0MixYY2ZkImWaSB72eZX0pGbMKoOk5e4nAvIRcHEcQc8Lk/BmHMBRmK10wsziUiedJJB5rDzTEy2cC1/+v5f2gsHfXNjEY0aJmvegzuD2PKC72TTofMnvzJz2abUUafgTjCRnGe3x4iTN5ZKUtx/89hfUahPcUD5H9hreRPVpFvEk/XV3yV3B3OhI2N1Lpops2R20qfdl/2VfKbhIklvHWEL1UoWmGUII6G4jOTr0FZoKOXwnlvasbTdkiFGgGI+EUgbgYh4+r8Z875ADNEF+Uwae1UWKHs7Brrf9pB/bvkrWJIr4q1bduMYMLb3sYjkjchlyfwd+5WIESIcAmQaB1V5ChLDSMOXudqAh9jnuibzNGkBjAcwMRTB+K0b5mTkwyXIJTUSIIHvco8IZLVoPWGrDX/nEamGuzqbGE="

	myClient, err := kadp.NewKADPClient(&configs.KmsConfig{
		Domain:           url,
		Credential:       token,
		RegisterToken:    RegisterToken,
		KeystoreFileName: "keystore1.jks",
		KeystorePassword: "123456",
	})
	if err != nil {
		b.Fatal(err)
	}

	label := "concurrent-benchmark-key"
	key, err := myClient.CreateCipherKey(32, label, 1)
	if err != nil {
		b.Fatal(err)
	}

	testData := make([]byte, 1024)
	_, err = rand.Read(testData)
	if err != nil {
		b.Fatal(err)
	}

	concurrentLevels := []int{1, 5, 10, 20}
	for _, workers := range concurrentLevels {
		b.Run(fmt.Sprintf("AES-Concurrent-%d", workers), func(b *testing.B) {
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				wg.Add(workers)

				for w := 0; w < workers; w++ {
					go func() {
						defer wg.Done()
						_, err := myClient.Encipher(&kadp.EncipherRequest{
							Plaintext: testData,
							CipherKey: key,
							Algorithm: kadp.AES,
							Mode:      kadp.ECB,
							Padding:   kadp.NoPadding,
							Label:     label,
						})
						if err != nil {
							b.Error(err)
						}
					}()
				}
				wg.Wait()
			}
		})
	}
}

// 吞吐量测试
func TestThroughput(t *testing.T) {
	logger.SetLevel(logger.ErrorLevel)

	url := "http://192.168.0.129:8190"
	RegisterToken := "hnludUczLOwZfj0t84j1Eh0btPVNviLgPSjOfuS8oKaNNLACoKUd56YNb31jzU+d"
	token := "epYu8UNoLOYNBJPYLVaTdCXCZvK7ku9leEyWZjA58DVqjJ8fLfbmO29T6Amusg45iR2WDsAbGgalED1iXD/rEMQiHkMEfcYVm5LCUFDACn/4uYJNqpgHbrttZD1lDkyDuKsYM0MixYY2ZkImWaSB72eZX0pGbMKoOk5e4nAvIRcHEcQc8Lk/BmHMBRmK10wsziUiedJJB5rDzTEy2cC1/+v5f2gsHfXNjEY0aJmvegzuD2PKC72TTofMnvzJz2abUUafgTjCRnGe3x4iTN5ZKUtx/89hfUahPcUD5H9hreRPVpFvEk/XV3yV3B3OhI2N1Lpops2R20qfdl/2VfKbhIklvHWEL1UoWmGUII6G4jOTr0FZoKOXwnlvasbTdkiFGgGI+EUgbgYh4+r8Z875ADNEF+Uwae1UWKHs7Brrf9pB/bvkrWJIr4q1bduMYMLb3sYjkjchlyfwd+5WIESIcAmQaB1V5ChLDSMOXudqAh9jnuibzNGkBjAcwMRTB+K0b5mTkwyXIJTUSIIHvco8IZLVoPWGrDX/nEamGuzqbGE="

	myClient, err := kadp.NewKADPClient(&configs.KmsConfig{
		Domain:           url,
		Credential:       token,
		RegisterToken:    RegisterToken,
		KeystoreFileName: "keystore1.jks",
		KeystorePassword: "123456",
	})
	if err != nil {
		t.Fatal(err)
	}

	label := "throughput-test-key2"
	_, err = myClient.CreateCipherKey(16, label, 1)
	if err != nil {
		t.Fatal(err)
	}

	// 测试不同数据大小的吞吐量
	dataSizes := []int{128, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 50 * 1024 * 1024} // bytes
	duration := 10 * time.Second                                                                                                 // 测试持续时间

	for _, size := range dataSizes {
		t.Run(fmt.Sprintf("Throughput-%dB", size), func(t *testing.T) {
			testData := make([]byte, size)
			_, err = rand.Read(testData)
			if err != nil {
				t.Fatal(err)
			}

			count := 0
			done := make(chan bool)

			// 在指定时间内持续发送请求
			go func() {
				time.Sleep(duration)
				done <- true
			}()

		encryptionLoop:
			for {
				select {
				case <-done:
					break encryptionLoop
				default:
					_, err := myClient.Encipher(&kadp.EncipherRequest{
						Plaintext: testData,
						//CipherKey: key,
						Algorithm: kadp.SM4,
						Mode:      kadp.ECB,
						Padding:   kadp.NoPadding,
						Label:     label,
					})
					if err != nil {
						t.Error(err)
						break encryptionLoop
					}
					count++
				}
			}

			throughput := float64(count) / duration.Seconds()
			dataRate := float64(count*size) / (1024 * 1024) / duration.Seconds() // MB/s

			t.Logf("数据大小: %d bytes, 总操作数: %d, 吞吐量: %.2f ops/sec, 数据速率: %.2f MB/s (%.2f Mbps)",
				size, count, throughput, dataRate, dataRate*8)
		})
	}
}
