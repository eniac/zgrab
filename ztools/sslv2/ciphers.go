/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package sslv2

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// CipherKind holds a 3-byte ID for a cipher spec. It is invalid for a
// CipherKind to be greater than 0x00FFFFFF
type CipherKind uint32

// Standard SSLv3 CipherKinds
const (
	SSL_CK_RC4_128_WITH_MD5              CipherKind = 0x010080
	SSL_CK_RC4_128_EXPORT40_WITH_MD5     CipherKind = 0x020080
	SSL_CK_RC2_128_CBC_WITH_MD5          CipherKind = 0x030080
	SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 CipherKind = 0x040080
	SSL_CK_IDEA_128_CBC_WITH_MD5         CipherKind = 0x050080
	SSL_CK_DES_64_CBC_WITH_MD5           CipherKind = 0x060040
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5     CipherKind = 0x0700C0
)

var AllCiphers = []CipherKind{
	SSL_CK_RC4_128_WITH_MD5,
	SSL_CK_RC4_128_EXPORT40_WITH_MD5,
	SSL_CK_RC2_128_CBC_WITH_MD5,
	SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
	SSL_CK_IDEA_128_CBC_WITH_MD5,
	SSL_CK_DES_64_CBC_WITH_MD5,
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
}

var nonExportCiphers = []CipherKind{
	SSL_CK_RC4_128_WITH_MD5,
	SSL_CK_RC2_128_CBC_WITH_MD5,
	SSL_CK_IDEA_128_CBC_WITH_MD5,
	SSL_CK_DES_64_CBC_WITH_MD5,
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
}

var ExportCiphers = []CipherKind{
	SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
	SSL_CK_RC4_128_EXPORT40_WITH_MD5,
}

// SSLv2CipherFromTLS returns an SSLv2 object representing a cipher from SSLv3
// or newer.
func SSLv2CipherFromTLS(newCipher uint32) CipherKind {
	return CipherKind(newCipher)
}

// MarshalBinary implements the binary marshaler interface
func (ck *CipherKind) MarshalSSLv2() ([]byte, error) {
	cku := uint32(*ck)
	// Ciphers can only be three bytes
	if cku > 0x00FFFFFF {
		return nil, fmt.Errorf("invalid cipher id %d", cku)
	}
	out := []byte{
		byte(cku >> 16),
		byte(cku >> 8),
		byte(cku),
	}
	return out, nil
}

// UnmarshalBinary implements the BinaryUnmarshler interface
func (ck *CipherKind) UnmarshalBinary(b []byte) error {
	if len(b) < 3 {
		return fmt.Errorf("buffer too short for CipherKind: %d", len(b))
	}
	var cku uint32
	cku = (uint32(b[0]) << 16) + (uint32(b[1]) << 8) + uint32(b[2])
	*ck = CipherKind(cku)
	return nil
}

func (ck *CipherKind) MarshalJSON() ([]byte, error) {
	name, ok := ciphersToNames[*ck]
	if !ok {
		return json.Marshal(strconv.Itoa(int(*ck)))
	}
	return json.Marshal(name)
}
