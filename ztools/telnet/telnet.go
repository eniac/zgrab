/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package telnet

import (
	"bytes"
	"errors"
	"net"
	"time"
)

var (
	IAC            = 0xFF //255 - Interpret as command
	DONT           = 0xFE
	DO             = 0xFD
	WONT           = 0xFC
	WILL           = 0xFB
	READ_TIMEOUT   = 3 * time.Second
	IAC_CMD_LENGTH = 3 // IAC commands take 3 bytes (inclusive)
)

func GetTelnetBanner(logStruct *TelnetLog, conn net.Conn) error {

	if err := NegotiateOptions(conn); err != nil {
		return err
	}

	//grab banner

	return nil

}

func NegotiateOptions(conn net.Conn) error {
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(READ_TIMEOUT))

	bytesRead := 0

	numBytes, err := conn.Read(buffer)

	bytesRead += numBytes
	if err != nil {
		return err
	}

	if bytesRead == len(buffer) {
		return errors.New("Not enough buffer space for telnet options")
	}

	// Negotiate options
	retBuffer := make([]byte, 1024)
	retBufferIndex := 0
	var option, optionType byte
	for iacIndex := bytes.IndexByte(buffer, IAC); iacIndex != -1; iacIndex = bytes.IndexByte(buffer, IAC) {
		optionType = bytes[iacIndex+1]
		option = bytes[iacIndex+2]

		if optionType == WILL || optionType == WONT {
			optionType = DONT
		} else if option == DO || optionType == DONT {
			optionType = WONT
		} else {
			return errors.New("Unsupported telnet option type")
		}

		retBuffer[retBufferIndex] = IAC
		retBuffer[retBufferIndex+1] = optionType
		retBuffer[retBufferIndex+2] = option

		retBufferIndex += IAC_CMD_LENGTH
	}

	if err = conn.Write(retBuffer); err != nil {
		return err
	}

	return nil
}