package cfb

import (
"bytes"
"crypto/aes"
"crypto/cipher"
"crypto/rand"
"encoding/base64"
"errors"
"fmt"
"io"
)

var (
  // ErrInvalidBlockSize indicates hash blocksize <= 0.
  ErrInvalidBlockSize = errors.New("invalid blocksize")

  // ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
  ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

  // ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
  ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

// pkcs7Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
func pkcs7Padding(b []byte, blocksize int) ([]byte, error) {
  if blocksize <= 0 {
    return nil, ErrInvalidBlockSize
  }
  if b == nil || len(b) == 0 {
    return nil, ErrInvalidPKCS7Data
  }
  n := blocksize - (len(b) % blocksize)
  pb := make([]byte, len(b)+n)
  copy(pb, b)
  copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
  return pb, nil
}

// pkcs7Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func pkcs7Trimming(b []byte, blocksize int) ([]byte, error) {
  if blocksize <= 0 {
    return nil, ErrInvalidBlockSize
  }
  if b == nil || len(b) == 0 {
    return nil, ErrInvalidPKCS7Data
  }
  if len(b)%blocksize != 0 {
    return nil, ErrInvalidPKCS7Padding
  }
  c := b[len(b)-1]
  n := int(c)
  if n == 0 || n > len(b) {
    return nil, ErrInvalidPKCS7Padding
  }
  for i := 0; i < n; i++ {
    if b[len(b)-n+i] != c {
      return nil, ErrInvalidPKCS7Padding
    }
  }
  return b[:len(b)-n], nil
}

func Encrypt(key []byte, plaintext []byte) (result []byte, encErr error) {
  // key := []byte(keyText)
  block, err := aes.NewCipher(key)
  if err != nil {
    return nil, err
  }
  plaintext, err = pkcs7Padding(plaintext, block.BlockSize())

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
func EncryptString(key []byte, text string) (string, error) {
  plaintext := []byte(text)
  ciphertext, err:= Encrypt(key, plaintext)
  if err != nil {
    return "", err
  }
  // convert to base64
  return base64.StdEncoding.EncodeToString(ciphertext), nil
}


func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
  block, err := aes.NewCipher(key)
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
  return pkcs7Trimming(ciphertext, aes.BlockSize)
}

// decrypt from base64 to decrypted string
func DecryptString(key []byte, cryptoText string) (string, error) {
  ciphertext, _ := base64.StdEncoding.DecodeString(cryptoText)
  ciphertext, err:=Decrypt(key, ciphertext)
  if err!=nil{
    return "", err
  }
  return fmt.Sprintf("%s", ciphertext), nil
}
