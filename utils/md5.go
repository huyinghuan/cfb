package utils

import (
  "encoding/base64"
  "crypto/md5"
)

func GetMD5(text string) string {
  hasher := md5.New()
  hasher.Write([]byte(text))
  return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}