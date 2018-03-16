package cbc

import (
  "testing"
  "log"
)

func TestCBC(t *testing.T) {
  cbc := New("helle world")
  result, e := cbc.EncryptString("zzz")
  if e!=nil{
    log.Println(e)
    t.Fail()
  }
  l, e:= cbc.DecryptString(result)
  if e!=nil{
    log.Println(e)
    t.Fail()
  }
  log.Println(l)
}
