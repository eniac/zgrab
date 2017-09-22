package ike

import (
	"errors"
	"github.com/zmap/zgrab/ztools/zlog"
	"io/ioutil"
	"net"
	"os"
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
	if len(pkgConfig.ProbeFile) > 0 {
		if err := ioutil.WriteFile(pkgConfig.ProbeFile, x, 0644); err != nil {
			zlog.Fatalf("Error writing to probe file \"%s\": %s", pkgConfig.ProbeFile, err.Error())
		} else {
			zlog.Info("Wrote probe file and exiting...")
			os.Exit(0)
		}
	}
	if len(x) > MAX_UDP_PAYLOAD_LEN {
		zlog.Fatalf("Message exceeds max udp payload length (disable this warning if you don't care)")
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
