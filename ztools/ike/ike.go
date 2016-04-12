package ike

import (
    "net"
)

// Initiator wraps a network connection with an IKE initiator connection
func Initiator(c net.Conn, config *Config) *Conn {
	return &Conn{
		conn:   c,
		config: config,
	}
}
