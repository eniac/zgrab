package ike

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/zmap/zgrab/ztools/zlog"
	"net"
	"strings"
	"time"
)

// Initiator implements an IKE initiator.
type Initiator struct {
	*Conn
}

func NewInitiator(c *Conn) *Initiator {
	return &Initiator{c}
}

// NewInitiatorConn establishes an IKE connection using c as the underlying
// transport.
func NewInitiatorConn(c net.Conn, addr string, config *InitiatorConfig) (*Conn, error) {
	fullConf := *config
	fullConf.SetDefaults() // set defaults for general Config
	fullConf.SetConfig()   // set initiator-specific config using pkgConfig options

	conn := &Conn{conn: c}

	if err := conn.initiatorHandshake(&fullConf); err != nil {
		c.Close()
		return nil, fmt.Errorf("ike: handshake failed: %v", err)
	}

	return conn, nil
}

// Dial initiates a connection to the given IKE responder.
func Dial(network, addr string, config *InitiatorConfig) (*Initiator, error) {
	conn, err := net.DialTimeout(network, addr, config.Timeout)
	if err != nil {
		return nil, err
	}

	if config.Timeout != 0 {
		conn.SetDeadline(time.Now().Add(config.Timeout))
	}

	c, err := NewInitiatorConn(conn, addr, config)
	if err != nil {
		return nil, err
	}

	return NewInitiator(c), nil
}

type InitiatorConfig struct {
	// Config contains configuration that is shared between IKE initiators and responders.
	Config

	// IKE Version (1 or 2)
	Version uint16 `json:"version"`

	// IKEv1 Mode ("aggressive" or "main")
	ModeV1 string `json:"exchange_type,omitempty"`

	// Diffie-Hellman group to send in the initiator key exchange message
	DHGroup uint16 `json:"dh_group"`

	// Diffie-Hellman key exchange value to send in the initiator key exchange message (must match DHGroup).
	KexValues [][]byte `json:"kex_value,omitempty"`

	// List of proposals to send in the initiator security association message.
	Proposals []Proposal `json:"proposals"`

	// Timeout is the maximum amount of time for the UDP connection to
	// establish.  A Timeout of zero means no timeout.
	Timeout time.Duration

	// BuiltIn specifies a built-in configuration that may overwrite other command-line options.
	BuiltIn string
}

func (c *Conn) initiatorHandshake(config *InitiatorConfig) (err error) {

	if _, err = config.Rand.Read(c.initiatorSPI[:]); err != nil {
		return errors.New("ike: unable to read from random")
	}

	if config.Version == VersionIKEv2 {
		return c.initiatorHandshakeV2(config)
	}
	if config.Version == VersionIKEv1 {
		if config.ModeV1 == "main" {
			return c.initiatorHandshakeMain(config)
		}
		if config.ModeV1 == "aggressive" {
			return c.initiatorHandshakeAggressive(config)
		}
	}
	return errors.New("ike: invalid initiator config")
}

func (c *Conn) initiatorHandshakeMain(config *InitiatorConfig) (err error) {
	// Send IKEv1 Main Mode SA message
	msg := c.buildInitiatorMainSA(config)
	if err = c.writeMessage(msg); err != nil {
		return
	}
	config.ConnLog.InitiatorMainSA = msg.MakeLog()

	var response *ikeMessage

	// Messages can come in any order and be retransmitted, so expect anything
	for config.ConnLog.ResponderMainSA == nil {

		// Read response
		response, err = c.readMessage()
		if err != nil {
			return
		}
		log := response.MakeLog()

		// Check if response contains an error notification and abort. Many implementations have invalid SPIs for this, so put it before the SPI check.
		if err = response.containsErrorNotification(); err != nil {
			config.ConnLog.ErrorNotification = response.MakeLog()
			return
		}

		// Verify that the SPI is correct. This could occur if we have two simultaneous connections with the host, so don't treat this as an error.
		if !bytes.Equal(c.initiatorSPI[:], response.hdr.initiatorSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid initiator SPI")
			continue
		}
		if !bytes.Equal(c.responderSPI[:], make([]byte, 8)) && !bytes.Equal(c.responderSPI[:], response.hdr.responderSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid responder SPI")
			continue
		}

		if response.containsPayload(SECURITY_ASSOCIATION_V1) {
			if config.ConnLog.ResponderMainSA == nil {
				config.ConnLog.ResponderMainSA = log
				copy(c.responderSPI[:], response.hdr.responderSPI[:])
				config.DHGroup = response.getResponderDHGroup()
				if config.DHGroup == 0 {
					err = errors.New("Unable to extract Diffie-Hellman group from responser Security Exchange")
					return
				}

				if _, ok := groupKexMap[config.DHGroup]; !ok {
					err = errors.New("Unsupported Diffie-Hellman group in responder Security Association")
					return
				}

			} else if bytes.Equal(log.Raw, config.ConnLog.ResponderMainSA.Raw) {
				// ignore retransmissions
			} else {
				// they sent two different SA messages back, which is unexpected
				config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			}
			continue
		}

		if response.containsPayload(KEY_EXCHANGE_V1) && response.containsPayload(NONCE_V1) {
			log := response.MakeLog()
			if config.ConnLog.ResponderMainKE == nil {
				// They sent a KE message before we did. Does not follow the RFC, but OK.
				config.ConnLog.ResponderMainKE = log
			} else if bytes.Equal(log.Raw, config.ConnLog.ResponderMainKE.Raw) {
				// ignore retransmissions
			} else {
				// they sent two different KE messages back, which is unexpected
				config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			}
			continue
		}

		// unexpected message
		config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
	}

	// Build IKEv1 Main Mode KE message
	msg = c.buildInitiatorMainKE(config)
	if err = c.writeMessage(msg); err != nil {
		return
	}
	config.ConnLog.InitiatorMainKE = msg.MakeLog()

	// Messages can come in any order and be retransmitted, so expect anything
	for config.ConnLog.ResponderMainKE == nil {

		// Read response
		response, err = c.readMessage()
		if err != nil {
			return
		}
		log := response.MakeLog()

		// Check if response contains an error notification and abort. Many implementations have invalid SPIs for this, so put it before the SPI check.
		if err = response.containsErrorNotification(); err != nil {
			config.ConnLog.ErrorNotification = response.MakeLog()
			return
		}

		// Verify that the SPI is correct. This could occur if we have two simultaneous connections with the host, so don't treat this as an error.
		if !bytes.Equal(c.initiatorSPI[:], response.hdr.initiatorSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid initiator SPI")
			continue
		}
		if !bytes.Equal(c.responderSPI[:], make([]byte, 8)) && !bytes.Equal(c.responderSPI[:], response.hdr.responderSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid responder SPI")
			continue
		}

		if response.containsPayload(SECURITY_ASSOCIATION_V1) {
			if config.ConnLog.ResponderMainSA == nil {
				zlog.Fatalf("execution error: config.ConnLog.ResponderMainSA should not be nil")
			} else if bytes.Equal(log.Raw, config.ConnLog.ResponderMainSA.Raw) {
				// ignore retransmissions
			} else {
				// they sent two different SA messages back, which is unexpected
				config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			}
			continue
		}

		if response.containsPayload(KEY_EXCHANGE_V1) && response.containsPayload(NONCE_V1) {
			if config.ConnLog.ResponderMainKE == nil {
				// They sent a KE message before we did. Does not follow the RFC, but OK.
				config.ConnLog.ResponderMainKE = log
			} else if bytes.Equal(log.Raw, config.ConnLog.ResponderMainKE.Raw) {
				// ignore retransmissions
			} else {
				// they sent two different KE messages back, which is unexpected
				config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			}
			continue
		}
		// unexpected message
		config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
	}

	// TODO: HASH_I and HASH_R messages
	return
}

func (c *Conn) buildInitiatorMainSA(config *InitiatorConfig) (msg *ikeMessage) {
	msg = new(ikeMessage)
	msg.hdr = new(ikeHeader)
	copy(msg.hdr.initiatorSPI[:], c.initiatorSPI[:])
	// msg.hdr.responderSPI
	msg.hdr.nextPayload = SECURITY_ASSOCIATION_V1
	msg.hdr.majorVersion = VersionIKEv1
	msg.hdr.minorVersion = 0
	msg.hdr.exchangeType = IDENTITY_PROTECTION_V1
	msg.hdr.flags = 0
	msg.hdr.messageId = 0           // Message ID
	msg.hdr.length = IKE_HEADER_LEN // header + body

	// add payloads
	payload1 := c.buildPayload(config, SECURITY_ASSOCIATION_V1)
	payload1.nextPayload = NO_NEXT_PAYLOAD
	msg.hdr.length += uint32(payload1.length)
	msg.payloads = append(msg.payloads, payload1)

	return
}

func (c *Conn) buildInitiatorMainKE(config *InitiatorConfig) (msg *ikeMessage) {
	msg = new(ikeMessage)
	msg.hdr = new(ikeHeader)
	if config.ConnLog.InitiatorMainSA == nil || config.ConnLog.ResponderMainSA == nil {
		return
	}
	copy(msg.hdr.initiatorSPI[:], c.initiatorSPI[:])
	copy(msg.hdr.responderSPI[:], c.responderSPI[:])
	msg.hdr.nextPayload = KEY_EXCHANGE_V1
	msg.hdr.majorVersion = VersionIKEv1
	msg.hdr.minorVersion = 0
	msg.hdr.exchangeType = IDENTITY_PROTECTION_V1
	msg.hdr.flags = 0
	msg.hdr.messageId = 0           // Message ID
	msg.hdr.length = IKE_HEADER_LEN // header + body

	// add payloads
	payload1 := c.buildPayload(config, KEY_EXCHANGE_V1)
	payload1.nextPayload = NONCE_V1
	msg.hdr.length += uint32(payload1.length)
	msg.payloads = append(msg.payloads, payload1)

	payload2 := c.buildPayload(config, NONCE_V1)
	payload2.nextPayload = NO_NEXT_PAYLOAD
	msg.hdr.length += uint32(payload2.length)
	msg.payloads = append(msg.payloads, payload2)

	return
}

func (c *Conn) initiatorHandshakeAggressive(config *InitiatorConfig) (err error) {

	// Send IKEv1 Aggressive Mode message
	msg := c.buildInitiatorAggressive(config)
	if err = c.writeMessage(msg); err != nil {
		return
	}
	config.ConnLog.InitiatorAggressive = msg.MakeLog()

	var response *ikeMessage

	// Messages can come in any order and be retransmitted, so expect anything
	for config.ConnLog.ResponderAggressive == nil {

		// Read response
		response, err = c.readMessage()
		if err != nil {
			return
		}
		log := response.MakeLog()

		// Check if response contains an error notification and abort. Many implementations have invalid SPIs for this, so put it before the SPI check.
		if err = response.containsErrorNotification(); err != nil {
			config.ConnLog.ErrorNotification = response.MakeLog()
			return
		}

		// Verify that the SPI is correct. This could occur if we have two simultaneous connections with the host, so don't treat this as an error.
		if !bytes.Equal(c.initiatorSPI[:], response.hdr.initiatorSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid initiator SPI")
			continue
		}
		if !bytes.Equal(c.responderSPI[:], make([]byte, 8)) && !bytes.Equal(c.responderSPI[:], response.hdr.responderSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid responder SPI")
			continue
		}

		if response.containsPayload(SECURITY_ASSOCIATION_V1) && response.containsPayload(KEY_EXCHANGE_V1) {
			config.ConnLog.ResponderAggressive = log
			continue
		}

		// unexpected message
		config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
	}
	return
}

func (c *Conn) buildInitiatorAggressive(config *InitiatorConfig) (msg *ikeMessage) {
	msg = new(ikeMessage)
	msg.hdr = new(ikeHeader)
	copy(msg.hdr.initiatorSPI[:], c.initiatorSPI[:])
	// msg.hdr.responderSPI
	msg.hdr.nextPayload = SECURITY_ASSOCIATION_V1
	msg.hdr.majorVersion = VersionIKEv1
	msg.hdr.minorVersion = 0
	msg.hdr.exchangeType = AGGRESSIVE_V1
	msg.hdr.flags = 0
	msg.hdr.messageId = 0           // Message ID
	msg.hdr.length = IKE_HEADER_LEN // header + body

	// add payloads
	payload1 := c.buildPayload(config, SECURITY_ASSOCIATION_V1)
	payload1.nextPayload = KEY_EXCHANGE_V1
	msg.hdr.length += uint32(payload1.length)
	msg.payloads = append(msg.payloads, payload1)

	payload2 := c.buildPayload(config, KEY_EXCHANGE_V1)
	payload2.nextPayload = NONCE_V1
	msg.hdr.length += uint32(payload2.length)
	msg.payloads = append(msg.payloads, payload2)

	payload3 := c.buildPayload(config, NONCE_V1)
	payload3.nextPayload = IDENTIFICATION_V1
	msg.hdr.length += uint32(payload3.length)
	msg.payloads = append(msg.payloads, payload3)

	payload4 := c.buildPayload(config, IDENTIFICATION_V1)
	payload4.nextPayload = NO_NEXT_PAYLOAD
	msg.hdr.length += uint32(payload4.length)
	msg.payloads = append(msg.payloads, payload4)

	return
}

func (c *Conn) initiatorHandshakeV2(config *InitiatorConfig) (err error) {

	// Send IKE_SA_INIT
	msg := c.buildInitiatorSAInit(config)
	if err = c.writeMessage(msg); err != nil {
		return
	}
	config.ConnLog.InitiatorSAInit = msg.MakeLog()

	var response *ikeMessage

	// Messages can come in any order and be retransmitted, so expect anything
	for config.ConnLog.ResponderSAInit == nil {

		// Read response
		response, err = c.readMessage()
		if err != nil {
			return
		}
		log := response.MakeLog()

		// Check if response contains an INVALID_KE_PAYLOAD request. If so, initiate another handshake with the requested group.
		if dhGroup := response.containsInvalidKEPayload(); dhGroup != 0 {
			config.DHGroup = dhGroup
			return c.initiatorHandshakeV2(config)
		}

		// Check if response contains an error notification and abort. Many implementations have invalid SPIs for this, so put it before the SPI check.
		if err = response.containsErrorNotification(); err != nil {
			config.ConnLog.ErrorNotification = response.MakeLog()
			return
		}

		// Verify that the SPI is correct. This could occur if we have two simultaneous connections with the host, so don't treat this as an error.
		if !bytes.Equal(c.initiatorSPI[:], response.hdr.initiatorSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid initiator SPI")
			continue
		}
		if !bytes.Equal(c.responderSPI[:], make([]byte, 8)) && !bytes.Equal(c.responderSPI[:], response.hdr.responderSPI[:]) {
			config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
			//err = errors.New("invalid responder SPI")
			continue
		}

		if response.containsPayload(SECURITY_ASSOCIATION_V2) && response.containsPayload(KEY_EXCHANGE_V2) {
			config.ConnLog.ResponderSAInit = log
			continue
		}

		// unexpected message
		config.ConnLog.Unexpected = append(config.ConnLog.Unexpected, log)
	}
	return
}

func (c *Conn) buildInitiatorSAInit(config *InitiatorConfig) (msg *ikeMessage) {
	msg = new(ikeMessage)
	msg.hdr = new(ikeHeader)
	copy(msg.hdr.initiatorSPI[:], c.initiatorSPI[:])
	// msg.hdr.responderSPI
	msg.hdr.nextPayload = SECURITY_ASSOCIATION_V2
	msg.hdr.majorVersion = VersionIKEv2
	msg.hdr.minorVersion = 0
	msg.hdr.exchangeType = IKE_SA_INIT_V2
	msg.hdr.flags = 0x08            // flags (bit 3 set)
	msg.hdr.messageId = 0           // Message ID
	msg.hdr.length = IKE_HEADER_LEN // header + body

	// add payloads
	payload1 := c.buildPayload(config, SECURITY_ASSOCIATION_V2)
	payload1.nextPayload = KEY_EXCHANGE_V2
	msg.hdr.length += uint32(payload1.length)
	msg.payloads = append(msg.payloads, payload1)

	payload2 := c.buildPayload(config, KEY_EXCHANGE_V2)
	payload2.nextPayload = NONCE_V2
	msg.hdr.length += uint32(payload2.length)
	msg.payloads = append(msg.payloads, payload2)

	payload3 := c.buildPayload(config, NONCE_V2)
	payload3.nextPayload = NO_NEXT_PAYLOAD
	msg.hdr.length += uint32(payload3.length)
	msg.payloads = append(msg.payloads, payload3)

	return
}

func (c *Conn) buildPayload(config *InitiatorConfig, payloadType uint8) (p *payload) {
	p = new(payload)
	p.payloadType = payloadType

	switch payloadType {
	//  IKEv1
	case SECURITY_ASSOCIATION_V1:
		p.body = c.buildPayloadSecurityAssociationV1(config)
	case KEY_EXCHANGE_V1:
		p.body = c.buildPayloadKeyExchangeV1(config)
	case IDENTIFICATION_V1:
		p.body = c.buildPayloadIdentificationV1(config)
	case CERTIFICATE_V1:
	case CERTIFICATE_REQUEST_V1:
	case HASH_V1:
	case SIGNATURE_V1:
	case NONCE_V1:
		p.body = c.buildPayloadNonce(config)
	case NOTIFICATION_V1:
	case DELETE_V1:
	case VENDOR_ID_V1:
		p.body = c.buildPayloadVendorId(config)
	//  IKEv2
	case SECURITY_ASSOCIATION_V2:
		p.body = c.buildPayloadSecurityAssociationV2(config)
	case KEY_EXCHANGE_V2:
		p.body = c.buildPayloadKeyExchangeV2(config)
	case IDENTIFICATION_INITIATOR_V2:
	case IDENTIFICATION_RESPONDER_V2:
	case CERTIFICATE_V2:
	case CERTIFICATE_REQUEST_V2:
	case AUTHENTICATION_V2:
	case NONCE_V2:
		p.body = c.buildPayloadNonce(config)
	case NOTIFY_V2:
	case DELETE_V2:
	case VENDOR_ID_V2:
		p.body = c.buildPayloadVendorId(config)
	case TRAFFIC_SELECTOR_INITIATOR_V2:
	case TRAFFIC_SELECTOR_RESPONDER_V2:
	case ENCRYPTED_V2:
	case CONFIGURATION_V2:
	case EXTENSIBLE_AUTHENTICATION_V2:
	default:
		zlog.Fatalf("unrecognized payload type: %v", p.payloadType)
	}

	return
}

func (c *Conn) buildPayloadSecurityAssociationV1(config *InitiatorConfig) (p *payloadSecurityAssociationV1) {
	p = new(payloadSecurityAssociationV1)
	p.doi = IPSEC_V1
	// situation is a bitmask
	sit := SIT_IDENTITY_ONLY_V1
	p.situation = make([]byte, 4)
	p.situation[0] = uint8(sit >> 24)
	p.situation[1] = uint8(sit >> 16)
	p.situation[2] = uint8(sit >> 8)
	p.situation[3] = uint8(sit)
	for _, proposalConfig := range config.Proposals {
		p.proposals = append(p.proposals, buildProposalV1(proposalConfig))
	}
	if len(p.proposals) > 0 {
		p.proposals[len(p.proposals)-1].lastProposal = true
	}
	return p
}

func buildTransformV1(transformConfig Transform) (t *transformV1) {
	t = new(transformV1)
	t.lastTransform = false
	t.transformNum = transformConfig.Num
	t.length = 8
	t.transformId = transformConfig.IdV1
	for _, attributeConfig := range transformConfig.Attributes {
		a := buildAttribute(attributeConfig)
		t.attributes = append(t.attributes, a)
		t.length += uint16(len(a.marshal()))
	}
	return
}

func buildProposalV1(proposalConfig Proposal) (p *proposalV1) {
	p = new(proposalV1)
	p.protocolId = PROTO_ISAKMP_V1
	p.proposalNum = proposalConfig.ProposalNum
	p.lastProposal = false
	p.spi = []byte{}

	for _, transformConfig := range proposalConfig.Transforms {
		t := buildTransformV1(transformConfig)
		p.transforms = append(p.transforms, t)
		p.length += t.length
	}
	return
}

func (c *Conn) buildPayloadSecurityAssociationV2(config *InitiatorConfig) (p *payloadSecurityAssociationV2) {
	p = new(payloadSecurityAssociationV2)
	for _, proposalConfig := range config.Proposals {
		p.proposals = append(p.proposals, buildProposalV2(proposalConfig))
	}
	if len(p.proposals) > 0 {
		p.proposals[len(p.proposals)-1].lastProposal = true
	}
	return p
}

func buildProposalV2(proposalConfig Proposal) (p *proposalV2) {
	p = new(proposalV2)
	p.protocolId = IKE_V2
	p.proposalNum = proposalConfig.ProposalNum
	p.lastProposal = false
	p.spi = []byte{}

	for _, transformConfig := range proposalConfig.Transforms {
		t := buildTransformV2(transformConfig)
		p.transforms = append(p.transforms, t)
		p.length += t.length
	}
	return
}

func buildTransformV2(transformConfig Transform) (t *transformV2) {
	t = new(transformV2)
	t.lastTransform = false
	t.transformType = transformConfig.Type
	t.length = 8
	t.transformId = transformConfig.Id
	for _, attributeConfig := range transformConfig.Attributes {
		a := buildAttribute(attributeConfig)
		t.attributes = append(t.attributes, a)
		t.length += uint16(len(a.marshal()))
	}
	return
}

func buildAttribute(attributeConfig Attribute) (a *attribute) {
	a = new(attribute)
	a.attributeType = attributeConfig.Type
	a.attributeValue = make([]byte, len(attributeConfig.Value))
	copy(a.attributeValue, attributeConfig.Value)
	return
}

func (c *Conn) buildPayloadKeyExchangeV1(config *InitiatorConfig) (p *payloadKeyExchangeV1) {
	p = new(payloadKeyExchangeV1)
	if len(config.KexValues) > 0 {
		p.keyExchangeData = append(p.keyExchangeData, config.KexValues[0]...)
		return
	}
	// TODO: generate random key here
	if val, ok := groupKexMap[config.DHGroup]; ok {
		p.keyExchangeData = append(p.keyExchangeData, val...)
	} else {
		zlog.Fatalf("unsupported group: %d", config.DHGroup)
	}
	return
}

func (c *Conn) buildPayloadKeyExchangeV2(config *InitiatorConfig) (p *payloadKeyExchangeV2) {
	p = new(payloadKeyExchangeV2)
	p.dhGroup = config.DHGroup
	if len(config.KexValues) > 0 {
		p.keyExchangeData = append(p.keyExchangeData, config.KexValues[0]...)
		return
	}
	// TODO: generate random key here
	if val, ok := groupKexMap[config.DHGroup]; ok {
		p.keyExchangeData = append(p.keyExchangeData, val...)
	} else {
		zlog.Fatalf("unsupported group: %d", p.dhGroup)
	}
	return
}

func (c *Conn) buildPayloadNonce(config *InitiatorConfig) (p *payloadNonce) {
	p = new(payloadNonce)
	// 48-byte nonce
	p.nonceData = append(p.nonceData, []byte("d3a261126ee5367a480154a1a1a3")...)
	p.nonceData = append(p.nonceData, []byte("f86ddd9e9c271cca03b413b8762c3648")...)
	p.nonceData = append(p.nonceData, []byte("f86ddd9e9c271cca03b413b8762c3648")...)
	p.nonceData = append(p.nonceData, []byte("9bc9")...)
	return
}

func (c *Conn) buildPayloadIdentificationV1(config *InitiatorConfig) (p *payloadIdentification) {
	p = new(payloadIdentification)
	p.idType = ID_USER_FQDN_V1
	p.idData = []byte{}
	return
}

func (c *Conn) buildPayloadVendorId(config *InitiatorConfig) (p *payloadVendorId) {
	p = new(payloadVendorId)
	return
}

func uint16ToBytes(num uint16) []byte {
	return []byte{uint8(num >> 8), uint8(num)}
}

func (c *InitiatorConfig) MakeBASELINE() {
	if c.Version == VersionIKEv1 {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				// AES-CBC-128, SHA1, DH_1024, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_1024_S160, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_S160_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_2048_S224, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_S224_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_2048_S256, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_S256_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_256_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_ECP_V1)},
				},
				},
				// AES-CBC-256, SHA1, DH_1024
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// AES-CBC-256, SHA1,  DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-256, SHA1, DH_256_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_ECP_V1)},
				},
				},
				// 1-DES, MD5, DH_1024, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(MD5_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// 3-DES, MD5, DH_1024, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(MD5_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// 3-DES, SHA1, DH_1024, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// 3-DES, SHA1, DH_1024, RSA_SIGNATURES
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// AES-CBC-256, SHA2_256,  DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-256, SHA2_256, DH_2048, RSA_SIGNATURES
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
			}},
		}
	} else {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_NONE_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_S160_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S224_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S256_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2},
			},
			},
			{ProposalNum: 2, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_512_256_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_384_192_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_256_128_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_S160_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S224_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S256_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2},
			},
			},
		}
	}
}

func (c *InitiatorConfig) MakeFORTIGATE() {
	if c.Version == VersionIKEv1 {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				// Send these ciphersuites first, since the attack is more efficient with smaller groups:

				// 3-DES, SHA1, DH_768, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_768_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_768, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_768_V1)},
				},
				},
				// 3-DES, SHA1, DH_1024, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_1024, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},

				// Default ciphersuites:

				// 3-DES, SHA1, DH_1536, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_1536, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},

				// Additional supported ciphersuites:

				// 3-DES, SHA1, DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-256, SHA2-256, DH_1536, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// AES-CBC-256, SHA2-512, DH_1536, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_512_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// AES-CBC-256, SHA2-256, DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-256, SHA2-512, DH_2048, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_512_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},

				// Try them all with RSA signatures instead of PSK
				// 3-DES, SHA1, DH_768, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_768_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_768, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_768_V1)},
				},
				},
				// 3-DES, SHA1, DH_1024, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_1024, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1)},
				},
				},
				// 3-DES, SHA1, DH_1536, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_1536, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// 3-DES, SHA1, DH_2048, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_2048, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-256, SHA2-256, DH_1536, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// AES-CBC-256, SHA2-512, DH_1536, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_512_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1)},
				},
				},
				// AES-CBC-256, SHA2-256, DH_2048, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
				// AES-CBC-256, SHA2-512, DH_2048, RSASignatures
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_512_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1)},
				},
				},
			}},
		}
	} else {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_DES_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_512_256_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_384_192_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_256_128_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_768_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1536_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_V2},
			},
			},
		}
	}
}

func (c *InitiatorConfig) MakeECDH_BASELINE() {
	if c.Version == VersionIKEv1 {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				// AES-CBC-128, SHA1, DH_224_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_224_ECP_V1)},
				},
				},
				// AES-CBC-224, SHA1, DH_224_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(224)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_224_ECP_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_256_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_ECP_V1)},
				},
				},
				// AES-CBC-256, SHA1, DH_256_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_ECP_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_384_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_384_ECP_V1)},
				},
				},
				// AES-CBC-256, SHA1, DH_384_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_384_ECP_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_521_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_521_ECP_V1)},
				},
				},
				// AES-CBC-256, SHA1, DH_521_ECP, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_521_ECP_V1)},
				},
				},
				// AES-CBC-128, SHA1, DH_256_BRAINPOOL, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_BRAINPOOL_V1)},
				},
				},
				// AES-CBC-256, SHA1, DH_256_BRAINPOOL, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_224_BRAINPOOL_V1)},
				},
				},
			}},
		}
	} else {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_NONE_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_224_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_384_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_521_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2},
			},
			},
			{ProposalNum: 2, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_512_256_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_384_192_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_256_128_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_224_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_384_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_521_ECP_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2},
			},
			},
		}
	}
}

func (c *InitiatorConfig) MakeSINGLE_GROUP() {
	if c.Version == VersionIKEv1 {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				// AES-CBC-128, SHA1, <group>, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(128)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(c.DHGroup)},
				},
				},
				// AES-CBC-256, SHA1, <group>, PSK
				{IdV1: KEY_IKE_V1, Attributes: []Attribute{
					{Type: KEY_LENGTH_V1, Value: uint16ToBytes(256)},
					{Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1)},
					{Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1)},
					{Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1)},
					{Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(c.DHGroup)},
				},
				},
			}},
		}
	} else {
		c.Proposals = []Proposal{
			{ProposalNum: 1, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_NONE_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: c.DHGroup},
			},
			},
			{ProposalNum: 2, Transforms: []Transform{
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []Attribute{{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128)}}},
				{Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2},
				{Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_512_256_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_384_192_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_256_128_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2},
				{Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2},
				{Type: DIFFIE_HELLMAN_GROUP_V2, Id: c.DHGroup},
			},
			},
		}
	}
}

func (c *InitiatorConfig) SetConfig() error {
	// Sanity check the IKE version.
	if pkgConfig.Version == 1 {
		c.Version = VersionIKEv1
	} else if pkgConfig.Version == 2 {
		c.Version = VersionIKEv2
	} else {
		return fmt.Errorf("ike: invalid version: %s", pkgConfig.Version)
	}

	// V1 and V2 group numbers are the same for the groups that both version support.
	configString := strings.ToUpper(pkgConfig.BuiltIn)
	switch configString {
	case "": // do not use a built-in config
	case "BASELINE":
		c.DHGroup = DH_1024_V1
		c.MakeBASELINE()
	case "FORTIGATE":
		c.DHGroup = DH_1536_V1
		c.MakeFORTIGATE()
	case "1024S160":
		c.DHGroup = DH_1024_S160_V1
		c.MakeSINGLE_GROUP()
	case "2048S224":
		c.DHGroup = DH_2048_S224_V1
		c.MakeSINGLE_GROUP()
	case "2048S256":
		c.DHGroup = DH_2048_S256_V1
		c.MakeSINGLE_GROUP()
	// check for subgroup order validation
	// 1
	case "1024S160_1":
		c.DHGroup = DH_1024_S160_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, make([]byte, 128))
		c.KexValues[0][127] = 0x01
	case "2048S224_1":
		c.DHGroup = DH_2048_S224_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, make([]byte, 224))
		c.KexValues[0][224] = 0x01
	case "2048S256_1":
		c.DHGroup = DH_2048_S256_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, make([]byte, 256))
		c.KexValues[0][255] = 0x01
	// p-1
	case "1024S160_M1":
		c.DHGroup = DH_1024_S160_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_DH_1024_S160_M1)
	case "2048S224_M1":
		c.DHGroup = DH_2048_S224_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_DH_2048_S224_M1)
	case "2048S256_M1":
		c.DHGroup = DH_2048_S256_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_DH_2048_S256_M1)
	// 0
	case "1024S160_0":
		c.DHGroup = DH_1024_S160_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, make([]byte, 128))
	case "2048S224_0":
		c.DHGroup = DH_2048_S224_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, make([]byte, 224))
	case "2048S256_0":
		c.DHGroup = DH_2048_S256_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, make([]byte, 256))
	// subgroup of order 7
	case "1024S160_S7":
		c.DHGroup = DH_1024_S160_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_DH_1024_S160_S7)
	// subgroup of order 3
	case "2048S224_S3":
		c.DHGroup = DH_2048_S224_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_DH_2048_S224_S3)
	// subgroup of order 7
	case "2048S256_S7":
		c.DHGroup = DH_2048_S256_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_DH_2048_S256_S7)

	// elliptic curve configs
	case "ECDH_BASELINE":
		c.DHGroup = DH_256_ECP_V1
		c.MakeECDH_BASELINE()
	case "256_ECP":
		c.DHGroup = DH_256_ECP_V1
		c.MakeSINGLE_GROUP()
	case "256_ECP_INVALID_S5":
		c.DHGroup = DH_256_ECP_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_256_ECP_INVALID_S5)
	case "256_ECP_TWIST_S5":
		c.DHGroup = DH_256_ECP_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_256_ECP_INVALID_S5)
	case "224_ECP":
		c.DHGroup = DH_224_ECP_V1
		c.MakeSINGLE_GROUP()
	case "224_ECP_INVALID_S13":
		c.DHGroup = DH_224_ECP_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_224_ECP_INVALID_S13)
	case "224_ECP_TWIST_S11":
		c.DHGroup = DH_224_ECP_V1
		c.MakeSINGLE_GROUP()
		c.KexValues = append(c.KexValues, KEX_224_ECP_TWIST_S11)
	case "384_ECP":
		c.DHGroup = DH_384_ECP_V1
		c.MakeSINGLE_GROUP()
	case "521_ECP":
		c.DHGroup = DH_521_ECP_V1
		c.MakeSINGLE_GROUP()
	case "256_BRAINPOOL":
		c.DHGroup = DH_256_BRAINPOOL_V1
		c.MakeSINGLE_GROUP()
	case "EC2N_155":
		c.DHGroup = DH_EC2N_GP_155_V1
		c.MakeSINGLE_GROUP()
	case "EC2N_185":
		c.DHGroup = DH_EC2N_GP_185_V1
		c.MakeSINGLE_GROUP()
	// Not yet standardized as of Nov. 2016: https://tools.ietf.org/html/draft-ietf-ipsecme-safecurves-05#section-2
	//case "CURVE25519":
	//    c.DHGroup = DH_CURVE25519_V2
	//    c.MakeSINGLE_GROUP()
	default:
		return fmt.Errorf("ike: invalid ike-config: %s", configString)
	}
	// Sanity-check the config
	if c.DHGroup == 0 {
		return fmt.Errorf("ike: invalid DH group: %s", c.DHGroup)
	}
	if len(c.Proposals) == 0 {
		return fmt.Errorf("ike: no proposals specified")
	}
	return nil
}

type Proposal struct {
	Raw         []byte      `json:"raw,omitempty"`
	ProposalNum uint8       `json:"proposal_num,omitempty"`
	ProtocolId  uint8       `json:"protocol_id,omitempty"`
	Spi         []byte      `json:"spi,omitempty"`
	Transforms  []Transform `json:"transforms,omitempty"`
}

type Transform struct {
	Raw        []byte      `json:"raw,omitempty"`
	Num        uint8       `json:"num,omitempty"`
	Attributes []Attribute `json:"attributes,omitempty"`
	// used in IKEv1
	IdV1 uint8 `json:"id_v1,omitempty"`
	// used in IKEv2
	Type uint8  `json:"type,omitempty"`
	Id   uint16 `json:"id,omitempty"`
}

type Attribute struct {
	Raw   []byte `json:"raw,omitempty"`
	Type  uint16 `json:"type"`
	Value []byte `json:"value"`
}
