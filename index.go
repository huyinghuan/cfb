package encryption

import "github.com/huyinghuan/encryption/cbc"
import "github.com/huyinghuan/encryption/cfb"

var CBC = cbc.New
var CFB = cfb.New
