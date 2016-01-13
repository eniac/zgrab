package netscape

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	MSG_CLIENT_HELLO byte = 1
	MSG_SERVER_HELLO byte = 2
)

var ErrInvalidLength = errors.New("Invalid SSLv2 packet length")

type Header struct {
	Length uint16
	raw    []byte
}

func (h *Header) MarshalBinary() (b []byte, err error) {
	if h.Length > uint16(32512) {
		err = ErrInvalidLength
		return
	}
	b = make([]byte, 2)
	b[0] = byte(h.Length >> 8)
	b[1] = byte(h.Length)
	return
}

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

func (h *ClientHello) MarshalBinary() (b []byte, err error) {
	// 1 byte flag + 2 byte version + 3 2-byte lengths of the variable len fields
	length := 1 + 2 + 2*3 + len(h.Ciphers) + len(h.SessionID) + len(h.Challenge)
	b = make([]byte, length)
	buf := b
	buf[0] = MSG_CLIENT_HELLO
	buf = buf[1:]
	binary.BigEndian.PutUint16(b, h.Version)
	buf = buf[2:]
	binary.BigEndian.PutUint16(b, uint16(len(h.Ciphers)))
	buf = buf[2:]
	binary.BigEndian.PutUint16(b, uint16(len(h.SessionID)))
	buf = buf[2:]
	binary.BigEndian.PutUint16(b, uint16(len(h.Challenge)))
	buf = buf[2:]
	copy(buf, h.Ciphers)
	buf = buf[len(h.Ciphers):]
	copy(buf, h.SessionID)
	buf = buf[len(h.SessionID):]
	copy(buf, h.Challenge)
	buf = buf[len(h.Challenge):]
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

func readRecord(c net.Conn) (b []byte, err error) {
	return
}

func Handshake(c net.Conn) error {
	ch := new(ClientHello)
	b, err := ch.MarshalBinary()
	if _, err = c.Write(b); err != nil {
		return err
	}
	return nil
}
