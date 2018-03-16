package encryption

import "encryption/cbc"
import "encryption/cfb"

var CBC = cbc.New
var CFB = cfb.New
