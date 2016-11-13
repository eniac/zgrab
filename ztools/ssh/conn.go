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

package ssh

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"regexp"
	"strconv"

	"github.com/keybase/go-crypto/brainpool"
)

type Conn struct {
	// Underlying network connection
	conn net.Conn

	config *Config

	// Key information
	macLength uint32

	// Log for ZGrab output
	handshakeLog HandshakeLog

	currentCipher cipher

	kexAlgorithm     string
	hostKeyAlgorithm string

	dropbearCompatMode bool
}

type sshPayload interface {
	MsgType() byte
	Marshal() ([]byte, error)
	Unmarshal([]byte) bool
}

var dropbearRegex = regexp.MustCompile(`^dropbear_([\d]+)\.([\d]+)`)

const (
	maxProtoSize = 256 * 8
)

func (c *Conn) ClientHandshake() error {
	clientProtocol := MakeZGrabProtocolAgreement()
	clientProtocolBytes := clientProtocol.Marshal()
	c.conn.Write(clientProtocolBytes)

	buf := make([]byte, maxProtoSize)
	protocolDone := false
	protocolRead := 0
	lineStart := 0
	lineEnd := 0

ProtocolLoop:
	for !protocolDone && protocolRead < maxProtoSize {

		// Read one "line"
		lineDone := false
		cur := lineStart
		for !lineDone && protocolRead < maxProtoSize {
			n, err := c.conn.Read(buf[cur : cur+1])
			cur += n
			protocolRead += n
			if err != nil {
				break ProtocolLoop
			}
			if cur-lineStart < 2 {
				continue
			}
			if buf[cur-1] == byte('\n') {
				lineDone = true
				lineEnd = cur
			}
		}

		// Check if it's the version banner
		line := buf[lineStart:lineEnd]
		lineStart = lineEnd
		if len(line) < 5 {
			continue
		}
		if !bytes.Equal(line[0:3], []byte("SSH")) {
			continue
		}
		protocolDone = true
	}
	serverProtocol := ProtocolAgreement{
		RawBanner: string(buf[0:protocolRead]),
	}
	serverProtocol.ParseRawBanner()
	c.handshakeLog.ServerProtocol = &serverProtocol
	if !protocolDone {
		return errInvalidProtocolVersion
	}

	serverSoftware := serverProtocol.SoftwareVersion
	if matches := dropbearRegex.FindStringSubmatch(serverSoftware); len(matches) == 3 {
		major, errMajor := strconv.Atoi(matches[1])
		minor, errMinor := strconv.Atoi(matches[2])
		if errMajor == nil && errMinor == nil && major == 0 && minor <= 46 {
			c.dropbearCompatMode = true
		}
	}

	// See if it matches????

	// Read the key options
	serverKex := new(KeyExchangeInit)
	err := c.readPacket(serverKex)
	if err != nil {
		return err
	}

	c.handshakeLog.ServerKeyExchangeInit = serverKex

	//
	ckxi, err := GenerateKeyExchangeInit(c.config)
	if err != nil {
		return err
	}
	if c.dropbearCompatMode {
		if len(c.config.HostKeyAlgorithms) == 0 {
			ckxi.KexAlgorithms = Dropbear_0_46.kexAlgorithms
		}
		ckxi.HostKeyAlgorithms = Dropbear_0_46.hostKeyAlgorithms
		ckxi.EncryptionClientToServer = Dropbear_0_46.encryptionAlgorithms
		ckxi.EncryptionServerToClient = Dropbear_0_46.encryptionAlgorithms
		ckxi.MACClientToServer = Dropbear_0_46.macAlgorithms
		ckxi.MACClientToServer = Dropbear_0_46.macAlgorithms
	}
	if err = c.writePacket(ckxi); err != nil {
		return err
	}

	if c.kexAlgorithm, err = chooseAlgorithm(ckxi.KexAlgorithms, serverKex.KexAlgorithms); err != nil {
		return err
	}

	c.handshakeLog.Algorithms = new(AlgorithmSelection)
	c.handshakeLog.Algorithms.KexAlgorithm = c.kexAlgorithm

	if c.hostKeyAlgorithm, err = chooseAlgorithm(ckxi.HostKeyAlgorithms, serverKex.HostKeyAlgorithms); err != nil {
		return err
	}
	c.handshakeLog.Algorithms.HostKeyAlgorithm = c.hostKeyAlgorithm

	switch c.kexAlgorithm {
	case KEX_DH_GROUP1_SHA1:
		if err := c.dhGroup1Kex(); err != nil {
			return err
		}
	case KEX_DH_GROUP14_SHA1:
		if err := c.dhGroup14Kex(); err != nil {
			return err
		}
	case KEX_DH_SHA1, KEX_DH_SHA256:
		if err := c.dhGroupExchange(); err != nil {
			return err
		}
	case KEX_CURVE_25519_SHA256_OPENSSH, KEX_ECDH_SHA2_NISTP224, KEX_ECDH_SHA2_NISTP256, KEX_ECDH_SHA2_NISTP384, KEX_ECDH_SHA2_NISTP521:
		if curve, ok := curveForCurveID(c.kexAlgorithm); ok {
			params := ECDHParams{
				SSHCurveID: c.kexAlgorithm,
				Curve:      curve,
			}
			if err := c.ecdhExchange(&params); err != nil {
				return err
			}
		}
	default:
		return errors.New("unimplemented kex method")
	}
	return nil
}

func curveForCurveID(id string) (elliptic.Curve, bool) {
	switch id {
	case KEX_CURVE_25519_SHA256_OPENSSH:
		return Curve25519(), true
	case KEX_ECDH_SHA2_BRAINPOOLP256:
		return brainpool.P256r1(), true
	case KEX_ECDH_SHA2_NISTP224:
		return elliptic.P224(), true
	case KEX_ECDH_SHA2_NISTP256:
		return elliptic.P256(), true
	case KEX_ECDH_SHA2_NISTP384:
		return elliptic.P384(), true
	case KEX_ECDH_SHA2_NISTP521:
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

func (c *Conn) HandshakeLog() *HandshakeLog {
	return &c.handshakeLog
}

func (c *Conn) readPacket(expected sshPayload) error {
	// Make a buffer of max packet size
	buf := make([]byte, 35001)
	totalRead, err := c.conn.Read(buf[0:4])
	if err != nil {
		return err
	}
	for totalRead < 4 {
		n, err := c.conn.Read(buf[totalRead:4])
		totalRead += n
		if err != nil {
			return err
		}
	}
	var p packet
	p.packetLength = binary.BigEndian.Uint32(buf[0:4])
	if p.packetLength > 35000 {
		return errLongPacket
	}
	totalLength := expectedLength(p.packetLength, c.macLength)
	for totalRead < totalLength {
		n, err := c.conn.Read(buf[totalRead:totalLength])
		totalRead += n
		if err != nil {
			return err
		}
	}
	// Fill out the rest of the packet
	b := buf[4:totalLength]

	// Read padding length
	if len(b) < 1 {
		return errShortPacket
	}
	p.paddingLength = b[0]
	b = b[1:]
	if uint32(p.paddingLength) > p.packetLength-1 {
		return errInvalidPadding
	}

	// Read the payload
	payloadLength := p.packetLength - uint32(p.paddingLength) - 1
	p.msgType = b[0]
	p.payload = b[1:payloadLength]
	b = b[payloadLength:]

	// Read the padding
	p.padding = b[0:p.paddingLength]
	b = b[p.paddingLength:]

	// Read the MAC, if applicable
	if uint32(len(b)) != c.macLength {
		return errShortPacket
	}

	if c.macLength > 0 {
		p.mac = b[0:c.macLength]
	}
	if len(p.payload) < 1 {
		return errShortPacket
	}
	if p.msgType != expected.MsgType() {
		return errUnexpectedMessage
	}
	if ok := expected.Unmarshal(p.payload); !ok {
		return errors.New("could not unmarshal")
	}

	return nil
}

func (c *Conn) writePacket(payload sshPayload) error {
	payloadBytes, err := payload.Marshal()
	msgType := payload.MsgType()
	if err != nil {
		return err
	}
	if len(payloadBytes) > 32768 {
		return errLongPacket
	}
	paddingLen := 8 - ((4 + 1 + 1 + len(payloadBytes)) % 8)
	if paddingLen < 4 {
		paddingLen += 8
	}
	paddingBytes := make([]byte, paddingLen)
	if len(paddingBytes) > 255 {
		return errInvalidPadding
	}
	pkt := packet{
		packetLength: uint32(2 + len(payloadBytes) + len(paddingBytes)),
		msgType:      msgType,
		payload:      payloadBytes,
		padding:      paddingBytes,
		mac:          []byte{},
	}
	out := make([]byte, 4+1+1+len(pkt.payload)+len(pkt.padding))
	binary.BigEndian.PutUint32(out, pkt.packetLength)
	out[4] = byte(len(pkt.padding))
	out[5] = pkt.msgType
	copy(out[6:], pkt.payload)
	copy(out[6+len(pkt.payload):], pkt.padding)

	written := 0
	for written < len(out) {
		n, err := c.conn.Write(out[written:])
		written += n
		if err != nil {
			return err
		}
	}
	written = 0
	mac := make([]byte, 0)
	for written < len(mac) {
		n, err := c.conn.Write(mac[written:])
		written += n
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) dhGroupExchange() error {
	gexRequest := new(KeyExchangeDHGroupRequest)
	gexRequest.Min = 1024
	gexRequest.Preferred = 3072
	gexRequest.Max = 8192
	if err := c.writePacket(gexRequest); err != nil {
		return err
	}
	gexParams := new(KeyExchangeDHGroupParameters)
	if err := c.readPacket(gexParams); err != nil {
		return err
	}
	c.handshakeLog.KexDHGroupParams = gexParams

	gexInit := new(KeyExchangeDHGroupInit)
	g := big.NewInt(0).SetBytes(gexParams.Generator.Bytes())
	p := big.NewInt(0).SetBytes(gexParams.Prime.Bytes())
	order := big.NewInt(0)
	order.Sub(p, big.NewInt(1))
	if len(c.config.KexValue) > 0 {
		gexInit.E.SetBytes(c.config.KexValue)
	} else if c.config.NegativeOne {
		one := big.NewInt(1)
		gexInit.E.Sub(p, one)
	} else {
		x, err := rand.Int(c.config.getRandom(), order)
		if err != nil {
			return err
		}
		gexInit.E.Exp(g, x, p)
	}
	if err := c.writePacket(gexInit); err != nil {
		return err
	}
	gexReply := new(KeyExchangeDHGroupReply)
	if err := c.readPacket(gexReply); err != nil {
		return err
	}
	c.handshakeLog.KexDHGroupReply = gexReply
	return nil
}

func (c *Conn) ecdhExchange(params *ECDHParams) error {
	var err error
	var mx, my *big.Int
	if params.Curve.Params().Name == "Curve25519" {
		mx, _ = new(big.Int).SetString("12519297798344875305557292433671964860635190053244199321010304085384576550016", 10)
		my, _ = new(big.Int).SetString("53030773923266012872098459210235568541521178854109831464468498685054132916945", 10)
	} else {
		_, mx, my, err = elliptic.GenerateKey(params.Curve, c.config.getRandom())
		if err != nil {
			return err
		}
	}
	switch c.config.KexConfig {
	case "224_ECP_TWIST_S11":
		// NIST-P224 generator of subgroup of order 11 on twist
		mx, _ = new(big.Int).SetString("21219928721835262216070635629075256199931199995500865785214182108232", 10)
		my, _ = new(big.Int).SetString("2486431965114139990348241493232938533843075669604960787364227498903", 10)
	case "224_ECP_INVALID_S13":
		// NIST-P224 generator of subgroup of order 13 on curve w/ B-1
		mx, _ = new(big.Int).SetString("1234919426772886915432358412587735557527373236174597031415308881584", 10)
		my, _ = new(big.Int).SetString("218592750580712164156183367176268299828628545379017213517316023994", 10)
	case "256_ECP_TWIST_S5":
		// NIST-P256 generator of subgroup of order 5 on twist
		// y^2 = x^3 + 64540953657701435357043644561909631465859193840763101878720769919119982834454*x + 21533133778103722695369883733312533132949737997864576898233410179589774724054
		mx, _ = new(big.Int).SetString("75610932410248387784210576211184530780201393864652054865721797292564276389325", 10)
		my, _ = new(big.Int).SetString("30046858919395540206086570437823256496220553255320964836453418613861962163895", 10)
	case "256_ECP_INVALID_S5":
		// NIST-P256 generator of subgroup of order 5 on curve w/ B-1
		mx, _ = new(big.Int).SetString("86765160823711241075790919525606906052464424178558764461827806608937748883041", 10)
		my, _ = new(big.Int).SetString("62096069626295534024197897036720226401219594482857127378802405572766226928611", 10)
	case "CURVE25519_S2":
		// Curve25519 generator of subgroup of order 2
		mx, _ = new(big.Int).SetString("19298681539552699237261830834781317975544997444273427339909597334652188435537", 10)
		my, _ = new(big.Int).SetString("0", 10)
	default:
		if len(c.config.KexConfig) > 0 {
			panic(c.config.KexConfig)
		}
	}
	ecdhi := new(KeyExchangeECDHInit)
	if params.Curve.Params().Name == "Curve25519" {
		_ = my
		mp := new(mpint)
		mp.SetBytes(mx.Bytes()) // convert between big.Int and mpint
		ecdhi.Q_C, _ = mp.Marshal()
	} else {
		ecdhi.Q_C = elliptic.Marshal(params.Curve, mx, my)
	}
	c.handshakeLog.ECDHInit = ecdhi
	c.writePacket(ecdhi)
	ecdhReply := new(KeyExchangeECDHInitReply)
	if err = c.readPacket(ecdhReply); err != nil {
		return err
	}

	c.handshakeLog.ECDHReply = ecdhReply
	return nil
}

func (c *Conn) dhExchange(params *DHParams) error {
	dhi := new(KeyExchangeDHInit)
	if len(c.config.KexValue) > 0 {
		dhi.E.SetBytes(c.config.KexValue)
	} else if c.config.NegativeOne {
		one := big.NewInt(1)
		dhi.E.Sub(params.Prime, one)
	} else {
		x, err := rand.Int(c.config.getRandom(), params.order)
		if err != nil {
			return err
		}
		E := big.NewInt(0)
		E.Exp(params.Generator, x, params.Prime)
		dhi.E.Set(E)
	}
	c.handshakeLog.DHInit = dhi
	c.writePacket(dhi)
	dhReply := new(KeyExchangeDHInitReply)
	if err := c.readPacket(dhReply); err != nil {
		return err
	}

	c.handshakeLog.DHReply = dhReply
	return nil
}

func (c *Conn) dhGroup1Kex() error {
	return c.dhExchange(&dhOakleyGroup2)
}

func (c *Conn) dhGroup14Kex() error {
	return c.dhExchange(&dhOakleyGroup14)
}
