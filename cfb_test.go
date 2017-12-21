package cfb

import (
  "testing"
  "fmt"
)

func TestAll(t *testing.T){
  key := []byte("~ec.huyinghuan@gmail.com")
  z, err := EncryptString(key, "1")
  if err != nil {
    t.Fatal(err)
  }
  o, err := DecryptString(key, z)
  if err != nil {
    t.Fatal(err)
  }
  fmt.Println(o)
}
