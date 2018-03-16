package cfb

import (
  "testing"
  "log"
)

func TestCBC(t *testing.T) {
  cfb := New("helle world")
  text:="zzz"
  result, e := cfb.EncryptString(text)
  if e!=nil{
    log.Println(e)
    t.Fail()
  }
  l, e:= cfb.DecryptString(result)
  if e!=nil{
    log.Println(e)
    t.Fail()
  }
  if text != l{
    t.Fail()
  }
}
