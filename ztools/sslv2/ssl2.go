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

	"github.com/zmap/zgrab/ztools/zlog"
)

// Protocol message codes
const (
	MSG_CLIENT_HELLO byte = 1
	MSG_SERVER_HELLO byte = 4
)

// Version codes
const (
	SSL_VERSION_2 uint16 = 0x0200
)

// ErrInvalidLength is returned when a byte slice to be Unmarshaled is too
// short, or when a single record length is greater than the max length of 32512
// bytes.
var ErrInvalidLength = errors.New("Invalid SSLv2 packet length")

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
	Length uint16
	raw    []byte
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
	h.Length = uint16(b[0]&0x7f)<<8 | uint16(b[1])
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
	zlog.Debug(buf[0:2])
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
	zlog.Debug(b)
	return
}

// UnmarshalBinary implements the BinaryUnmarshaler interface
func (h *ClientHello) UnmarshalBinary(b []byte) (err error) {
	return
}

type ServerHello struct {
	SessionIDHit    byte
	CertificateType byte
	Version         uint16
	Certificates    []byte
	Ciphers         []byte
	ConnectionID    []byte
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
	copy(buf, h.Certificates)
	buf = buf[len(h.Certificates):]

	copy(buf, h.Ciphers)
	buf = buf[len(h.Ciphers):]

	copy(buf, h.ConnectionID)
	buf = buf[len(h.ConnectionID):]

	// And we're done
	return
}

// UnmarshalBinary implements the BinaryUnmarshaler interface
func (h *ServerHello) UnmarshalBinary(b []byte) (err error) {
	return
}

func readRecord(c net.Conn) (b []byte, err error) {
	header := make([]byte, 2)
	_, err = c.Read(header)
	if err != nil {
		zlog.Debug(err.Error())
	}
	zlog.Debug(header)
	return
}

func writeRecord(c net.Conn, b []byte) (err error) {
	h := Header{
		Length: uint16(len(b)),
	}
	zlog.Debug(h.Length)
	var headerBytes []byte
	if headerBytes, err = h.MarshalBinary(); err != nil {
		return
	}
	record := append(headerBytes, b...)
	if _, err = c.Write(record); err != nil {
		return
	}
	readRecord(c)
	return nil
}

func Handshake(c net.Conn) error {
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
	if _, err := rand.Read(ch.Challenge); err != nil {
		return err
	}
	b, err := ch.MarshalBinary()
	if err = writeRecord(c, b); err != nil {
		return err
	}
	return nil
}
