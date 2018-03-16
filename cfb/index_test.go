package cfb

import (
  "testing"
  "log"
)

func TestCBC(t *testing.T) {
  cfb := New("helle world")
  result, e := cfb.EncryptString("zzz")
  if e!=nil{
    log.Println(e)
    t.Fail()
  }
  l, e:= cfb.DecryptString(result)
  if e!=nil{
    log.Println(e)
    t.Fail()
  }
  log.Println(l)
}
