# CFB encrypt content
---------------

key's length must is 24

## Install

```

dep ensure -add github.com/huyinghuan/encryption

```

## CBC

### New(key string)

### Encrypt

    func Encrypt(plaintext []byte) (result []byte, encErr error) {}

### EncryptString

    func EncryptString(text string) (string, error) {}
    
### Decrypt

    func Decrypt(ciphertext []byte) ([]byte, error){}
    
### DecryptString

    func DecryptString(cryptoText string) (string, error) {}

## CFB

### Encrypt

    func Encrypt(plaintext []byte) (result []byte, encErr error) {}

### EncryptString

    func EncryptString(text string) (string, error) {}
    
### Decrypt

    func Decrypt(ciphertext []byte) ([]byte, error){}
    
### DecryptString

    func DecryptString(cryptoText string) (string, error) {}

### Demo    

```
package main

import (
  "github.com/huyinghuan/encryption/cbc"
  "log"
)

func main(){
  encrypt := cbc.New("helle world")
  result, e := encrypt.EncryptString("zzz")
  if e!=nil{
    log.Println(e)
    return
  }
  l, e:= encrypt.DecryptString(result)
  if e!=nil{
    log.Println(e)
    return
  }
  log.Println(l)
}
```
