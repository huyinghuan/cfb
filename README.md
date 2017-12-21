# CFB encrypt content
---------------

key's length must is 24
## Install

```
dep ensure -add github.com/huyinghuan/cfb
```


## func

### Encrypt

func Encrypt(key []byte, plaintext []byte) (result []byte, encErr error) {}


### EncryptString

func EncryptString(key []byte, text string) (string, error) {}

### Decrypt

func Decrypt(key []byte, ciphertext []byte) ([]byte, error){}


### DecryptString

func DecryptString(key []byte, cryptoText string) (string, error) {}
