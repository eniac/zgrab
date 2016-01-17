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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"

	"github.com/zmap/zgrab/ztools/x509"
)

// Protocol message codes
const (
	MSG_CLIENT_HELLO byte = 1
	MSG_SERVER_HELLO byte = 4
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

// CipherKind holds a 3-byte ID for a cipher spec. It is invalid for a
// CipherKind to be greater than 0x00FFFFFF
type CipherKind uint32

// Stanard SSLv3 CipherKinds
const (
	SSL_CK_RC4_128_WITH_MD5              CipherKind = 0x010080
	SSL_CK_RC4_128_EXPORT40_WITH_MD5     CipherKind = 0x020080
	SSL_CK_RC2_128_CBC_WITH_MD5          CipherKind = 0x030080
	SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 CipherKind = 0x040080
	SSL_CK_IDEA_128_CBC_WITH_MD5         CipherKind = 0x050080
	SSL_CK_DES_64_CBC_WITH_MD5           CipherKind = 0x060040
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5     CipherKind = 0x0700C0
)

var defaultCiphers = []CipherKind{
	SSL_CK_RC4_128_WITH_MD5,
	SSL_CK_RC4_128_EXPORT40_WITH_MD5,
	SSL_CK_RC2_128_CBC_WITH_MD5,
	SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
	SSL_CK_IDEA_128_CBC_WITH_MD5,
	SSL_CK_DES_64_CBC_WITH_MD5,
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
}

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

type ClientHello struct {
	Version   uint16
	Ciphers   []byte
	SessionID []byte
	Challenge []byte
}

// MarshalBinary implements the BinaryMarshaler interface
func (h *ClientHello) MarshalBinary() (b []byte, err error) {
	// 1 byte flag + 2 byte version + 3 2-byte lengths of the variable len fields
	length := 1 + 2 + 2*3 + len(h.Ciphers) + len(h.SessionID) + len(h.Challenge)
	b = make([]byte, length)
	buf := b
	buf[0] = MSG_CLIENT_HELLO
	buf = buf[1:]
	binary.BigEndian.PutUint16(buf, h.Version)
	buf = buf[2:]
	binary.BigEndian.PutUint16(buf, uint16(len(h.Ciphers)))
	buf = buf[2:]
	binary.BigEndian.PutUint16(buf, uint16(len(h.SessionID)))
	buf = buf[2:]
	binary.BigEndian.PutUint16(buf, uint16(len(h.Challenge)))
	buf = buf[2:]
	copy(buf, h.Ciphers)
	buf = buf[len(h.Ciphers):]
	copy(buf, h.SessionID)
	buf = buf[len(h.SessionID):]
	copy(buf, h.Challenge)
	buf = buf[len(h.Challenge):]
	return
}

// UnmarshalBinary implements the BinaryUnmarshaler interface
func (h *ClientHello) UnmarshalBinary(b []byte) (err error) {
	return
}

type ServerHello struct {
	SessionIDHit    byte                `json:"session_id_hit"`
	CertificateType byte                `json:"certificate_type"`
	Version         uint16              `json:"version"`
	RawCertificates []byte              `json:"raw_certificates,omitempty"`
	Certificates    []*x509.Certificate `json:"certificates,omitempty"`
	Ciphers         []byte              `json:"ciphers,omitempty"`
	ConnectionID    []byte              `json:"connection_id,omitempty"`

	raw []byte
}

// MarshalBinary implements the BinaryMarshaler interface
func (h *ServerHello) MarshalBinary() (b []byte, err error) {
	// 1 byte version
	// 1 byte did-hit-session-id
	// 1 byte certificate type
	// 2 byte version
	// Three 2-byte lengths for each variable length field
	// The fields themselves
	length := 1 + 1 + 1 + 2 + 2*3 + len(h.Certificates) + len(h.Ciphers) + len(h.ConnectionID)
	b = make([]byte, length)
	buf := b
	buf[0] = MSG_SERVER_HELLO
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

	copy(buf, h.Ciphers)
	buf = buf[len(h.Ciphers):]

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
	if b[0] != MSG_SERVER_HELLO {
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
	h.Ciphers = buf[0:cipherSpecsLength]
	buf = buf[cipherSpecsLength:]
	h.ConnectionID = buf[0:connectionIDLength]
	h.raw = b[0:totalLength]

	// Parse the certificates
	h.Certificates, _ = x509.ParseCertificates(h.RawCertificates)
	return
}

func readRecord(c net.Conn) (b []byte, err error) {
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
	header := new(Header)
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

type HandshakeData struct {
	ClientHello *ClientHello `json:"client_hello,omitempty"`
	ServerHello *ServerHello `json:"server_hello,omitempty"`
}

func ClientHandshake(c net.Conn) (hs *HandshakeData, err error) {
	ch := new(ClientHello)
	// Assign ciphers
	ch.Version = SSL_VERSION_2
	ch.Ciphers = make([]byte, 3*len(defaultCiphers))
	for idx, cipher := range defaultCiphers {
		b := ch.Ciphers[3*idx : 3*idx+3]
		b[0] = byte((cipher & 0x00FF0000) >> 16)
		b[1] = byte((cipher & 0x0000FF00) >> 8)
		b[2] = byte(cipher)
	}
	ch.Challenge = make([]byte, 16)
	if _, err = rand.Read(ch.Challenge); err != nil {
		return
	}
	var b []byte
	if b, err = ch.MarshalBinary(); err != nil {
		return
	}
	if err = writeRecord(c, b); err != nil {
		return
	}
	if b, err = readRecord(c); err != nil {
		return
	}
	sh := new(ServerHello)
	hs = new(HandshakeData)
	hs.ServerHello = sh
	if err = sh.UnmarshalBinary(b); err != nil {
		return
	}
	return hs, nil
}
