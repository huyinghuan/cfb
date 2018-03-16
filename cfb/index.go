package cfb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/huyinghuan/encryption/utils"
)

type CFB struct {
	Key []byte
}

func New(key string) *CFB {
	cbc := new(CFB)
	cbc.Key = []byte(utils.GetMD5(key))
	return cbc
}

func (cfb *CFB) Encrypt(plaintext []byte) (result []byte, encErr error) {
	// key := []byte(keyText)
	block, err := aes.NewCipher(cfb.Key)
	if err != nil {
		return nil, err
	}
	plaintext, err = utils.PKCS7Padding(plaintext, block.BlockSize())

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	// convert to base64
	return ciphertext, nil
}

// encrypt string to base64 crypto using AES key长24位
func (cfb *CFB) EncryptString(text string) (string, error) {
	plaintext := []byte(text)
	ciphertext, err := cfb.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	// convert to base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (cfb *CFB) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(cfb.Key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)
	return utils.PKCS7Trimming(ciphertext, aes.BlockSize)
}

// decrypt from base64 to decrypted string
func (cfb *CFB) DecryptString(cryptoText string) (string, error) {
	ciphertext, _ := base64.StdEncoding.DecodeString(cryptoText)
	ciphertext, err := cfb.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s", ciphertext), nil
}
