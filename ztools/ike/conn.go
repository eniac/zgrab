package ike

import (
	"errors"
	"net"
	//    "io/ioutil"
)

type Conn struct {
	// Underlying network connection
	conn net.Conn

	// State for handshake
	initiatorSPI [8]byte
	responderSPI [8]byte
}

func (c *Conn) writeMessage(msg *ikeMessage) error {
	x := msg.marshal()
	//  Use this to print out zmap probe packet
	//    _ = ioutil.WriteFile("fortigate.v1.pkt", x, 0644)
	//  panic("WROTE FILE")
	if len(x) > MAX_UDP_PAYLOAD_LEN {
		panic("message exceeds max udp payload length (disable this warning if you don't care)")
	}
	n, err := c.Write(x)
	if err != nil {
		return err
	}
	if n != len(x) {
		return errors.New("unable to write message to connection")
	}
	return nil
}

// Write len(b) bytes to the connection, and return an error on failure
func (c *Conn) Write(b []byte) (written int, err error) {
	for written < len(b) {
		n, err := c.conn.Write(b[written:])
		written += n
		if err != nil {
			return written, err
		}
	}
	return
}

// Read an IKE message from the connection
func (c *Conn) readMessage() (msg *ikeMessage, err error) {
	raw := make([]byte, MAX_IKE_MESSAGE_LEN)

	var n int
	if n, err = c.conn.Read(raw); err != nil {
		return
	} else {
		raw = raw[:n]
	}

	msg = new(ikeMessage)
	if ok := msg.unmarshal(raw); !ok {
		err = errors.New("unable to parse ike message")
		return
	}

	return
}
