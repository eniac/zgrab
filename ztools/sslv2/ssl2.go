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
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"github.com/zmap/zgrab/ztools/x509"
	"github.com/zmap/zgrab/ztools/zlog"
)

// Protocol message codes
const (
	MSG_TYPE_CLIENT_HELLO      byte = 1
	MSG_TYPE_SERVER_HELLO      byte = 4
	MSG_TYPE_CLIENT_MASTER_KEY byte = 2
)

// Version codes
const (
	SSL_VERSION_2 uint16 = 0x0002
)

// ErrInvalidLength is returned when a byte slice to be Unmarshaled is too
// short, or when a single record length is greater than the max length of 32512
// bytes.
var ErrInvalidLength = errors.New("Invalid SSLv2 packet length")

var ErrUnexpectedMessage = errors.New("Unexpected message type")

type Header struct {
	Length        uint16
	PaddingLength uint8
	raw           []byte
}

// MarshalBinary implements the BinaryMarshaler interface
func (h *Header) MarshalBinary() (b []byte, err error) {
	if h.Length > uint16(16383) {
		err = ErrInvalidLength
		return
	}
	b = make([]byte, 2)
	b[0] = byte(h.Length >> 8)
	b[1] = byte(h.Length)
	b[0] |= 0x80
	return
}

// UnmarshalBinary implements the BinaryUnmarshaler interface
func (h *Header) UnmarshalBinary(b []byte) (err error) {
	if len(b) < 2 {
		return ErrInvalidLength
	}
	hasPadding := b[0]&0x80 == 0
	if hasPadding && len(b) < 3 {
		return ErrInvalidLength
	}
	h.Length = uint16(b[0]&0x7f)<<8 | uint16(b[1])
	if hasPadding {
		h.PaddingLength = b[2]
		h.raw = b[0:3]
	} else {
		h.raw = b[0:2]
	}
	return
}

// MarshalBinary implements the BinaryMarshaler interface
func (h *ServerHello) MarshalBinary() (b []byte, err error) {
	// 1 byte version
	// 1 byte did-hit-session-id
	// 1 byte certificate type
	// 2 byte version
	// Three 2-byte lengths for each variable length field
	// The fields themselves
	length := 1 + 1 + 1 + 2 + 2*3 + len(h.Certificates) + 3*len(h.Ciphers) + len(h.ConnectionID)
	b = make([]byte, length)
	buf := b
	buf[0] = MSG_TYPE_SERVER_HELLO
	buf[1] = h.SessionIDHit
	buf[2] = h.CertificateType
	buf = buf[3:]

	// Version
	binary.BigEndian.PutUint16(buf, h.Version)
	buf = buf[2:]

	// Put in all the lengths
	binary.BigEndian.PutUint16(buf, uint16(len(h.Certificates)))
	buf = buf[2:]

	binary.BigEndian.PutUint16(buf, uint16(len(h.Ciphers)))
	buf = buf[2:]

	binary.BigEndian.PutUint16(buf, uint16(len(h.ConnectionID)))
	buf = buf[2:]

	// Copy all the remaining fields
	copy(buf, h.RawCertificates)
	buf = buf[len(h.RawCertificates):]

	encodedCiphers := buf
	for idx, cipher := range h.Ciphers {
		b := encodedCiphers[3*idx : 3*idx+3]
		b[0] = byte((cipher & 0x00FF0000) >> 16)
		b[1] = byte((cipher & 0x0000FF00) >> 8)
		b[2] = byte(cipher)
	}

	copy(buf, encodedCiphers)
	buf = buf[len(encodedCiphers):]

	copy(buf, h.ConnectionID)
	buf = buf[len(h.ConnectionID):]

	// And we're done
	return
}

// UnmarshalBinary implements the BinaryUnmarshaler interface
func (h *ServerHello) UnmarshalBinary(b []byte) (err error) {
	if len(b) < 11 {
		return ErrInvalidLength
	}
	if b[0] != MSG_TYPE_SERVER_HELLO {
		return ErrUnexpectedMessage
	}
	h.SessionIDHit = b[1]
	h.CertificateType = b[2]
	h.Version = binary.BigEndian.Uint16(b[3:5])
	certificateLength := int(binary.BigEndian.Uint16(b[5:7]))
	cipherSpecsLength := int(binary.BigEndian.Uint16(b[7:9]))
	connectionIDLength := int(binary.BigEndian.Uint16(b[9:11]))
	variableLength := certificateLength + cipherSpecsLength + connectionIDLength
	totalLength := 11 + variableLength

	buf := b[11:]
	if len(buf) < variableLength {
		return ErrInvalidLength
	}
	h.RawCertificates = buf[0:certificateLength]
	buf = buf[certificateLength:]

	if cipherSpecsLength%3 != 0 {
		return fmt.Errorf("invalid cipher specs length %d, must be a multiple of 3", cipherSpecsLength)
	}

	h.Ciphers = make([]CipherKind, cipherSpecsLength/3)
	for idx := range h.Ciphers {
		b := buf[3*idx : 3*idx+3]
		h.Ciphers[idx].UnmarshalBinary(b)
	}
	buf = buf[cipherSpecsLength:]
	h.ConnectionID = buf[0:connectionIDLength]
	h.raw = b[0:totalLength]

	// Parse the certificates
	h.Certificates, _ = x509.ParseCertificates(h.RawCertificates)
	return
}

func readRecord(c net.Conn) (header Header, b []byte, err error) {
	headerBytes := make([]byte, 2)
	_, err = c.Read(headerBytes)
	if err != nil {
		return
	}
	// Check to see if it's a 3-byte header
	if headerBytes[0]&0x80 == 0 {
		headerBytes = append(headerBytes, byte(0))
		if _, err = c.Read(headerBytes[2:]); err != nil {
			return
		}
	}
	if err = header.UnmarshalBinary(headerBytes); err != nil {
		return
	}
	body := make([]byte, header.Length)
	var n int
	n, err = c.Read(body)
	if err != nil {
		b = body[0:n]
		return
	}
	b = body
	return
}

func writeRecord(c net.Conn, b []byte) (err error) {
	h := Header{
		Length: uint16(len(b)),
	}
	var headerBytes []byte
	if headerBytes, err = h.MarshalBinary(); err != nil {
		return
	}
	record := append(headerBytes, b...)
	if _, err = c.Write(record); err != nil {
		return
	}
	return nil
}

func decrypt(readCipher interface{}, b []byte) (d []byte, err error) {
	payload := b
	//zlog.Debug(len(payload))
	d = make([]byte, len(payload))
	switch c := readCipher.(type) {
	case cipher.Stream:
		c.XORKeyStream(d, payload)
	case cbcMode:
		blockSize := c.BlockSize()

		if l := len(payload); l%blockSize != 0 {
			return nil, fmt.Errorf("record length %d is not a multiple of block size %d", l, c.BlockSize())
		}

		c.CryptBlocks(d, payload)
	default:
		panic("unimplemented cipher")
	}
	return
}

type HandshakeData struct {
	ClientHello  *ClientHello  `json:"client_hello,omitempty"`
	ServerHello  *ServerHello  `json:"server_hello,omitempty"`
	ServerVerify *ServerVerify `json:"server_verify,omitempty"`
}

func ClientHandshake(c net.Conn, config *Config) (hs *HandshakeData, err error) {
	ch := new(ClientHello)
	ch.Version = SSL_VERSION_2
	// Assign ciphers
	var ciphers []CipherKind
	if len(config.Ciphers) == 0 {
		ciphers = AllCiphers
	} else {
		ciphers = config.Ciphers
	}
	ch.Ciphers = ciphers
	ch.Challenge = make([]byte, 16)
	for idx := range ch.Challenge {
		ch.Challenge[idx] = 0x02
	}
	var b []byte
	var h Header
	if b, err = ch.MarshalBinary(); err != nil {
		return
	}
	if err = writeRecord(c, b); err != nil {
		return
	}
	if h, b, err = readRecord(c); err != nil {
		return
	}
	sh := new(ServerHello)
	hs = new(HandshakeData)
	hs.ClientHello = ch
	hs.ServerHello = sh
	if err = sh.UnmarshalBinary(b); err != nil {
		return
	}
	if len(sh.Certificates) == 0 {
		err = errors.New("could not parse certificate")
		return
	}

	chosenCipherKind, ok := findCommonCipher(ciphers, sh.Ciphers)
	if !ok {
		zlog.Debug("no matching cipher")
		chosenCipherKind = SSL_CK_DES_64_CBC_WITH_MD5
	}

	var chosenCipher *cipherSuite
	for _, c := range cipherImplementations {
		if c.id == chosenCipherKind {
			chosenCipher = c
		}
	}

	cert := sh.Certificates[0]
	var pubKey *rsa.PublicKey
	pubKey, ok = cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		err = errors.New("certificate does not contain an RSA key")
	}

	masterKey := make([]byte, chosenCipher.encKeyLen+chosenCipher.clearKeyLen)
	for idx := range masterKey {
		masterKey[idx] = byte(idx)
	}

	cmk := new(ClientMasterKey)
	cmk.CipherKind = chosenCipherKind
	cmk.ClearKey = masterKey[0:chosenCipher.clearKeyLen]
	/*
		if config.ExtraPlaintext {
			cmk.ClearKey = append(cmk.ClearKey, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}...)
		}
	*/
	cmk.EncryptedKey, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, masterKey[chosenCipher.clearKeyLen:])
	cmk.KeyArg = make([]byte, chosenCipher.keyArgLen)
	for idx := range cmk.KeyArg {
		cmk.KeyArg[idx] = byte(idx)
	}
	if b, err = cmk.MarshalSSLv2(); err != nil {
		return
	}
	if err = writeRecord(c, b); err != nil {
		return
	}
	if h, b, err = readRecord(c); err != nil {
		return
	}
	hs.ServerVerify = new(ServerVerify)
	hs.ServerVerify.Raw = b
	clientReadKey, clientWriteKey := chosenCipher.deriveKey(masterKey, ch.Challenge, sh.ConnectionID)
	zlog.Debug(hex.EncodeToString(clientReadKey))
	zlog.Debug(hex.EncodeToString(clientWriteKey))
	readCipher := chosenCipher.cipher(clientReadKey, cmk.KeyArg, true)
	var d []byte
	d, err = decrypt(readCipher, b)
	d = d[0 : len(d)-int(h.PaddingLength)]
	zlog.Debug(d[16])
	zlog.Debug(d[17:])
	hs.ServerVerify.Decrypted = d[17:]
	return hs, nil
}
