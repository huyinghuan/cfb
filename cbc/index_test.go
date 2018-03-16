package cbc

import (
  "testing"
  "log"
)

func TestCBC(t *testing.T) {
  cbc := New("helle world")
  text:="zzz"
  result, e := cbc.EncryptString(text)
  if e!=nil{
    log.Println(e)
    t.Fail()
  }
  l, e:= cbc.DecryptString(result)
  if e!=nil{
    log.Println(e)
    t.Fail()
  }
  if text != l{
    t.Fail()
  }
}
