package ike

import (
	"errors"
)

type ikeMessage struct {
	raw      []byte
	hdr      *ikeHeader
	payloads []*payload
}

func (p *ikeMessage) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}

	x = make([]byte, IKE_HEADER_LEN)

	// set nextPayload fields
	nextPayload := NO_NEXT_PAYLOAD
	for i := len(p.payloads) - 1; i >= 0; i-- {
		p.payloads[i].nextPayload = nextPayload
		nextPayload = p.payloads[i].payloadType
	}
	p.hdr.nextPayload = nextPayload

	for _, payload := range p.payloads {
		x = append(x, payload.marshal()...)
	}

	p.hdr.length = uint32(len(x))
	copy(x[:IKE_HEADER_LEN], p.hdr.marshal())

	return
}

func (p *ikeMessage) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)

	// parse header
	p.hdr = new(ikeHeader)
	if ok := p.hdr.unmarshal(p.raw); !ok {
		return false
	}

	// truncating p.hdr.length (uint32) to a signed int
	if len(data) != int(p.hdr.length) {
		return false
	}

	curr := IKE_HEADER_LEN

	nextPayload := p.hdr.nextPayload
	for curr < int(p.hdr.length) && nextPayload != NO_NEXT_PAYLOAD {
		pa := new(payload)
		pa.payloadType = nextPayload
		if ok := pa.unmarshal(data[curr:]); !ok {
			return false
		}
		p.payloads = append(p.payloads, pa)
		curr += int(pa.length)
		nextPayload = pa.nextPayload
	}

	if curr != int(p.hdr.length) {
		return false
	}

	p.raw = p.raw[:curr]

	return true
}

// Check if this message contains a specific payload
func (p *ikeMessage) containsPayload(payloadType uint8) bool {
	// Check if this is a notification message
	for _, payload := range p.payloads {
		switch payload.payloadType {
		case payloadType:
			return true
		}
	}
	return false
}

// Check if the message contains an INVALID_KE_PAYLOAD, and return the requested group
func (p *ikeMessage) containsInvalidKEPayload() uint16 {
	for _, payload := range p.payloads {
		switch payload.payloadType {
		case NOTIFY_V2:
			if pa, ok := payload.body.(*payloadNotifyV2); ok {
				if pa.notifyType == INVALID_KE_PAYLOAD_V2 {
					if len(pa.notifyData) == 2 {
						return uint16(pa.notifyData[0])<<8 | uint16(pa.notifyData[1])
					}
				}
			}
		}
	}
	return 0
}

func (p *ikeMessage) containsErrorNotification() error {
	// Check if this is a notification message
	for _, payload := range p.payloads {
		switch payload.payloadType {
		case NOTIFICATION_V1:
			if pa, ok := payload.body.(*payloadNotifyV1); ok {
				if pa.notifyType >= 1 && pa.notifyType <= 16383 {
					// Error range
					return errors.New("received error notification (V1)")
				}
			}
		case NOTIFY_V2:
			if pa, ok := payload.body.(*payloadNotifyV2); ok {
				if pa.notifyType >= 1 && pa.notifyType <= 16383 {
					// Error range
					return errors.New("received error notification (V2)")
				}
			}
		}
	}
	return nil
}

// Extract responder DH group from Security Association message
func (p *ikeMessage) getResponderDHGroup() uint16 {
	for _, payload := range p.payloads {
		switch payload.payloadType {
		case SECURITY_ASSOCIATION_V1:
			if pa, ok := payload.body.(*payloadSecurityAssociationV1); ok {
				for _, proposal := range pa.proposals {
					for _, tr := range proposal.transforms {
						for _, at := range tr.attributes {
							if at.attributeType == GROUP_DESCRIPTION_V1 {
								if len(at.attributeValue) == 2 {
									return uint16(at.attributeValue[0])<<8 | uint16(at.attributeValue[1])
								}
							}
						}
					}
				}
			}
		}
	}
	return 0
}

// IKEv1 and IKEv2 share the same message header format
type ikeHeader struct {
	raw          []byte
	initiatorSPI [8]byte
	responderSPI [8]byte
	nextPayload  uint8
	majorVersion uint8
	minorVersion uint8
	exchangeType uint8
	flags        uint8
	messageId    uint32
	length       uint32
}

func (p *ikeHeader) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}
	x = make([]byte, IKE_HEADER_LEN)
	copy(x[:8], p.initiatorSPI[:])
	copy(x[8:16], p.responderSPI[:])
	x[16] = uint8(p.nextPayload)
	x[17] = uint8(p.majorVersion)<<4 | uint8(p.minorVersion)
	x[18] = uint8(p.exchangeType)
	x[19] = uint8(p.flags)
	x[20] = uint8(p.messageId >> 24)
	x[21] = uint8(p.messageId >> 16)
	x[22] = uint8(p.messageId >> 8)
	x[23] = uint8(p.messageId)
	x[24] = uint8(p.length >> 24)
	x[25] = uint8(p.length >> 16)
	x[26] = uint8(p.length >> 8)
	x[27] = uint8(p.length)

	return
}

func (p *ikeHeader) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)

	if len(data) < IKE_HEADER_LEN {
		return false
	}

	copy(p.initiatorSPI[:], data[:8])
	copy(p.responderSPI[:], data[8:16])
	p.nextPayload = uint8(data[16])
	p.majorVersion = uint8(data[17]&0xF0) >> 4
	p.minorVersion = uint8(data[17] & 0x0F)
	p.exchangeType = uint8(data[18])
	p.flags = uint8(data[19])
	p.messageId = uint32(data[20])<<24 |
		uint32(data[21])<<16 |
		uint32(data[22])<<8 |
		uint32(data[23])
	p.length = uint32(data[24])<<24 |
		uint32(data[25])<<16 |
		uint32(data[26])<<8 |
		uint32(data[27])

	p.raw = p.raw[:IKE_HEADER_LEN]

	return true
}

type payload struct {
	raw         []byte
	payloadType uint8
	nextPayload uint8
	reserved    uint8
	length      uint16
	body        payloadBody
}

type payloadBody interface {
	marshal() []byte
	unmarshal([]byte) bool
}

func (p *payload) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}
	x = make([]byte, IKE_PAYLOAD_HEADER_LEN)
	x[0] = p.nextPayload
	x[1] = p.reserved

	switch p.payloadType {
	//  IKEv1
	case SECURITY_ASSOCIATION_V1:
		if pa, ok := p.body.(*payloadSecurityAssociationV1); !ok {
			return
		} else {
			x = append(x, pa.marshal()...)
		}
	case KEY_EXCHANGE_V1:
		if pa, ok := p.body.(*payloadKeyExchangeV1); !ok {
			return
		} else {
			x = append(x, pa.marshal()...)
		}
	case IDENTIFICATION_V1:
		if pa, ok := p.body.(*payloadIdentification); !ok {
			return
		} else {
			x = append(x, pa.marshal()...)
		}
	case CERTIFICATE_V1:
		if pa, ok := p.body.(*payloadCertificate); !ok {
			return
		} else {
			x = append(x, pa.marshal()...)
		}
	case CERTIFICATE_REQUEST_V1:
		if pa, ok := p.body.(*payloadCertificateRequest); !ok {
			return
		} else {
			x = append(x, pa.marshal()...)
		}
	case HASH_V1:
		if pa, ok := p.body.(*payloadHashV1); !ok {
			return
		} else {
			x = append(x, pa.marshal()...)
		}
	case SIGNATURE_V1:
	case NONCE_V1:
		if pa, ok := p.body.(*payloadNonce); !ok {
			return
		} else {
			x = append(x, pa.marshal()...)
		}
	case NOTIFICATION_V1:
		if pa, ok := p.body.(*payloadNotifyV1); !ok {
			return
		} else {
			x = append(x, pa.marshal()...)
		}
	case VENDOR_ID_V1:
		if pa, ok := p.body.(*payloadVendorId); !ok {
			return
		} else {
			x = append(x, pa.marshal()...)
		}
	//  IKEv2
	case SECURITY_ASSOCIATION_V2:
		if sa, ok := p.body.(*payloadSecurityAssociationV2); !ok {
			return
		} else {
			x = append(x, sa.marshal()...)
		}
	case KEY_EXCHANGE_V2:
		if sa, ok := p.body.(*payloadKeyExchangeV2); !ok {
			return
		} else {
			x = append(x, sa.marshal()...)
		}
	case IDENTIFICATION_INITIATOR_V2:
		if sa, ok := p.body.(*payloadIdentification); !ok {
			return
		} else {
			x = append(x, sa.marshal()...)
		}
	case IDENTIFICATION_RESPONDER_V2:
		if sa, ok := p.body.(*payloadIdentification); !ok {
			return
		} else {
			x = append(x, sa.marshal()...)
		}
	case CERTIFICATE_V2:
		if sa, ok := p.body.(*payloadCertificate); !ok {
			return
		} else {
			x = append(x, sa.marshal()...)
		}
	case CERTIFICATE_REQUEST_V2:
		if sa, ok := p.body.(*payloadCertificateRequest); !ok {
			return
		} else {
			x = append(x, sa.marshal()...)
		}
	case AUTHENTICATION_V2:
	case NONCE_V2:
		if sa, ok := p.body.(*payloadNonce); !ok {
			return
		} else {
			x = append(x, sa.marshal()...)
		}
	case NOTIFY_V2:
		if sa, ok := p.body.(*payloadNotifyV2); !ok {
			return
		} else {
			x = append(x, sa.marshal()...)
		}
	case VENDOR_ID_V2:
		if sa, ok := p.body.(*payloadVendorId); !ok {
			return
		} else {
			x = append(x, sa.marshal()...)
		}
	default:
		return
	}

	p.length = uint16(len(x))
	x[2] = uint8(p.length >> 8)
	x[3] = uint8(p.length)

	return
}

func (p *payload) unmarshal(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	p.nextPayload = uint8(data[0])
	p.reserved = uint8(data[1])
	p.length = uint16(data[2])<<8 | uint16(data[3])

	if int(p.length) < IKE_PAYLOAD_HEADER_LEN {
		return false
	}

	if len(data) < int(p.length) {
		return false
	}

	p.raw = append(p.raw, data[:p.length]...)

	switch p.payloadType {
	//  IKEv1
	case SECURITY_ASSOCIATION_V1:
		pa := new(payloadSecurityAssociationV1)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case KEY_EXCHANGE_V1:
		pa := new(payloadKeyExchangeV1)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case IDENTIFICATION_V1:
		pa := new(payloadIdentification)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case CERTIFICATE_V1:
		pa := new(payloadCertificate)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case CERTIFICATE_REQUEST_V1:
		pa := new(payloadCertificateRequest)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case HASH_V1:
	case SIGNATURE_V1:
	case NONCE_V1:
		pa := new(payloadNonce)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case NOTIFICATION_V1:
		pa := new(payloadNotifyV1)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case DELETE_V1:
	case VENDOR_ID_V1:
		pa := new(payloadVendorId)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case SA_KEK_PAYLOAD_V1:
	case SA_TEK_PAYLOAD_V1:
	case KEY_DOWNLOAD_V1:
	case SEQUENCE_NUMBER_V1:
	case PROOF_OF_POSSESSION_V1:
	case NAT_DISCOVERY_V1:
	case NAT_ORIGINAL_ADDRESS_V1:
	case GROUP_ASSOCIATED_POLICY_V1:
	//  IKEv2
	case SECURITY_ASSOCIATION_V2:
		sa := new(payloadSecurityAssociationV2)
		if ok := sa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = sa
		}
	case KEY_EXCHANGE_V2:
		pa := new(payloadKeyExchangeV2)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case IDENTIFICATION_INITIATOR_V2:
		pa := new(payloadIdentification)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case IDENTIFICATION_RESPONDER_V2:
		pa := new(payloadIdentification)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case CERTIFICATE_V2:
		pa := new(payloadCertificate)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case CERTIFICATE_REQUEST_V2:
		pa := new(payloadCertificateRequest)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case AUTHENTICATION_V2:
	case NONCE_V2:
		pa := new(payloadNonce)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case NOTIFY_V2:
		pa := new(payloadNotifyV2)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case DELETE_V2:
	case VENDOR_ID_V2:
		pa := new(payloadVendorId)
		if ok := pa.unmarshal(p.raw[IKE_PAYLOAD_HEADER_LEN:]); !ok {
			return false
		} else {
			p.body = pa
		}
	case TRAFFIC_SELECTOR_INITIATOR_V2:
	case TRAFFIC_SELECTOR_RESPONDER_V2:
	case ENCRYPTED_V2:
	case CONFIGURATION_V2:
	case EXTENSIBLE_AUTHENTICATION_V2:
	case GENERIC_SECURE_PASSWORD_METHOD_V2:
	case GROUP_IDENTIFICATION_V2:
	case GROUP_SECURITY_ASSOCIATION_V2:
	case KEY_DOWNLOAD_V2:
	case ENCRYPTED_AND_AUTHENTICATED_FRAGMENT_V2:
	default:
		// unrecognized payload type
		return false
	}
	return true
}

type payloadSecurityAssociationV1 struct {
	raw       []byte
	doi       uint32
	situation []byte
	proposals []*proposalV1
}

func (p *payloadSecurityAssociationV1) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}

	x = make([]byte, 4)
	x[0] = uint8(p.doi >> 24)
	x[1] = uint8(p.doi >> 16)
	x[2] = uint8(p.doi >> 8)
	x[3] = uint8(p.doi)
	x = append(x, p.situation...)

	// set the lastPropoal field to true for the last proposal in the list
	if len(p.proposals) > 0 {
		p.proposals[len(p.proposals)-1].lastProposal = true
	}
	for _, proposal := range p.proposals {
		x = append(x, proposal.marshal()...)
	}

	return
}

func (p *payloadSecurityAssociationV1) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)

	if len(data) < 4 {
		return false
	}

	p.doi = uint32(data[0])<<24 |
		uint32(data[1])<<16 |
		uint32(data[2])<<8 |
		uint32(data[3])
	if p.doi == IPSEC_V1 {
		p.situation = append(p.situation, data[4:8]...)
	}

	data = data[8:]

	for len(data) > 0 {
		pr := new(proposalV1)
		if ok := pr.unmarshal(data); !ok {
			return false
		} else {
			data = data[len(pr.raw):]
			p.proposals = append(p.proposals, pr)
			if pr.lastProposal {
				break
			}
		}
	}

	if len(data) > 0 {
		return false
	}

	return true
}

type payloadSecurityAssociationV2 struct {
	raw       []byte
	proposals []*proposalV2
}

// IKEv1 only
type proposalV1 struct {
	raw          []byte
	lastProposal bool // 2 if more, 0 if last
	reserved     uint8
	length       uint16
	proposalNum  uint8
	protocolId   uint8
	spi          []byte
	transforms   []*transformV1
}

func (p *proposalV1) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}

	x = make([]byte, 8)
	x = append(x, p.spi...)

	if len(p.transforms) > 0 {
		p.transforms[len(p.transforms)-1].lastTransform = true
	}
	transformNum := uint8(1) // transform numbers start at 1
	for _, transform := range p.transforms {
		transform.transformNum = transformNum
		transformNum += 1
		x = append(x, transform.marshal()...)
	}

	if p.lastProposal {
		x[0] = uint8(0)
	} else {
		x[0] = uint8(2)
	}
	x[1] = uint8(p.reserved)
	x[2] = uint8(len(x) >> 8)
	x[3] = uint8(len(x))
	x[4] = uint8(p.proposalNum)
	x[5] = uint8(p.protocolId)
	x[6] = uint8(len(p.spi))
	x[7] = uint8(len(p.transforms))

	return
}

func (p *proposalV1) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)

	if len(data) < 8 {
		return false
	}

	if uint8(data[0]) == 0 {
		p.lastProposal = true
	} else {
		p.lastProposal = false
	}
	p.reserved = uint8(data[1])
	p.length = uint16(data[2])<<8 | uint16(data[3])
	p.proposalNum = uint8(data[4])
	p.protocolId = uint8(data[5])
	p.spi = make([]byte, int(data[6]))
	p.transforms = make([]*transformV1, int(data[7]))

	data = data[8:]
	length := 8

	if len(data) < len(p.spi) {
		return false
	}
	copy(p.spi, data)
	length += len(p.spi)

	data = data[len(p.spi):]
	transformNum := 0
	for len(data) > 0 && transformNum < len(p.transforms) && length < int(p.length) {
		t := new(transformV1)
		if ok := t.unmarshal(data); !ok {
			return false
		} else {
			length += len(t.raw)
			data = data[len(t.raw):]
			p.transforms[transformNum] = t
			transformNum += 1
			if t.lastTransform {
				break
			}
		}
	}

	if length != int(p.length) || transformNum != len(p.transforms) {
		return false
	}
	p.raw = p.raw[:length]

	return true
}

// IKEv1 only
type transformV1 struct {
	raw           []byte
	lastTransform bool // 3 if more, 0 if last
	reserved1     uint8
	length        uint16
	transformNum  uint8
	transformId   uint8
	reserved2     uint16
	attributes    []*attribute
}

func (p *transformV1) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}

	x = make([]byte, 8)

	for _, attribute := range p.attributes {
		x = append(x, attribute.marshal()...)
	}

	if p.lastTransform {
		x[0] = uint8(0)
	} else {
		x[0] = uint8(3)
	}
	x[1] = p.reserved1
	x[2] = uint8(len(x) >> 8)
	x[3] = uint8(len(x))
	x[4] = uint8(p.transformNum)
	x[5] = uint8(p.transformId)
	x[6] = uint8(p.reserved2 >> 8)
	x[7] = uint8(p.reserved2)

	return
}

func (p *transformV1) unmarshal(data []byte) bool {
	p.raw = append([]byte{}, data...)

	if len(data) < 8 {
		return false
	}

	if uint8(data[0]) == 0 {
		p.lastTransform = true
	} else {
		p.lastTransform = false
	}
	p.reserved1 = uint8(data[1])
	p.length = uint16(data[2])<<8 | uint16(data[3])
	p.transformNum = uint8(data[4])
	p.transformId = uint8(data[5])
	p.reserved2 = uint16(data[6])<<8 | uint16(data[7])
	p.attributes = make([]*attribute, 0)

	data = data[8:]
	length := 8

	for len(data) > 0 && length < int(p.length) {
		a := new(attribute)
		if ok := a.unmarshal(data); !ok {
			return false
		} else {
			length += len(a.raw)
			data = data[len(a.raw):]
			p.attributes = append(p.attributes, a)
		}
	}

	if length != int(p.length) {
		return false
	}

	p.raw = p.raw[:length]

	return true
}

// IKEv1 and IKEv2
type attribute struct {
	raw            []byte
	attributeType  uint16
	attributeValue []byte
}

func (p *attribute) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}

	x = make([]byte, 4)
	x[0] = uint8(p.attributeType >> 8)
	x[1] = uint8(p.attributeType)

	if uint8(p.attributeType>>15) == 0 {
		// TLV format
		x[2] = uint8(len(p.attributeValue) >> 8)
		x[3] = uint8(len(p.attributeValue))
		x = append(x, p.attributeValue...)
	} else {
		// TV format
		x[2] = uint8(p.attributeValue[0])
		x[3] = uint8(p.attributeValue[1])
	}
	return
}

func (p *attribute) unmarshal(data []byte) bool {

	if len(data) < 4 {
		return false
	}

	p.attributeType = uint16(data[0])<<8 | uint16(data[1])

	if (p.attributeType >> 15) == 0 {
		// TLV format
		length := int(uint16(data[2])<<8 | uint16(data[3]))
		if len(data) < 4+length {
			return false
		}
		p.raw = data[:4+length]
		p.attributeValue = append([]byte{}, data[4:4+length]...)
	} else {
		// TV format
		if len(data) < 4 {
			return false
		}
		p.raw = data[:4]
		p.attributeValue = append([]byte{}, data[2:4]...)
	}

	return true
}

func (p *payloadSecurityAssociationV2) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}

	// set the lastPropoal field to true for the last proposal in the list
	if len(p.proposals) > 0 {
		p.proposals[len(p.proposals)-1].lastProposal = true
	}
	for _, proposal := range p.proposals {
		x = append(x, proposal.marshal()...)
	}

	return
}

func (p *payloadSecurityAssociationV2) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)

	for len(data) > 0 {
		pr := new(proposalV2)
		if ok := pr.unmarshal(data); !ok {
			return false
		} else {
			data = data[len(pr.raw):]
			p.proposals = append(p.proposals, pr)
			if pr.lastProposal {
				break
			}
		}
	}

	if len(data) > 0 {
		return false
	}

	return true
}

type proposalV2 struct {
	raw          []byte
	lastProposal bool // 2 if more, 0 if last
	reserved     uint8
	length       uint16
	proposalNum  uint8
	protocolId   uint8
	spi          []byte
	transforms   []*transformV2
}

func (p *proposalV2) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}

	x = make([]byte, 8)
	x = append(x, p.spi...)

	if len(p.transforms) > 0 {
		p.transforms[len(p.transforms)-1].lastTransform = true
	}
	for _, transform := range p.transforms {
		x = append(x, transform.marshal()...)
	}

	if p.lastProposal {
		x[0] = uint8(0)
	} else {
		x[0] = uint8(2)
	}
	x[1] = uint8(p.reserved)
	x[2] = uint8(len(x) >> 8)
	x[3] = uint8(len(x))
	x[4] = uint8(p.proposalNum)
	x[5] = uint8(p.protocolId)
	x[6] = uint8(len(p.spi))
	x[7] = uint8(len(p.transforms))

	return
}

func (p *proposalV2) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)

	if len(data) < 8 {
		return false
	}

	if uint8(data[0]) == 0 {
		p.lastProposal = true
	} else {
		p.lastProposal = false
	}
	p.reserved = uint8(data[1])
	p.length = uint16(data[2])<<8 | uint16(data[3])
	p.proposalNum = uint8(data[4])
	p.protocolId = uint8(data[5])
	p.spi = make([]byte, int(data[6]))
	p.transforms = make([]*transformV2, int(data[7]))

	data = data[8:]
	length := 8

	if len(data) < len(p.spi) {
		return false
	}
	copy(p.spi, data)
	length += len(p.spi)

	data = data[len(p.spi):]
	numTransforms := 0
	for len(data) > 0 && numTransforms < len(p.transforms) && length < int(p.length) {
		t := new(transformV2)
		if ok := t.unmarshal(data); !ok {
			return false
		} else {
			length += len(t.raw)
			data = data[len(t.raw):]
			p.transforms[numTransforms] = t
			numTransforms += 1
			if t.lastTransform {
				break
			}
		}
	}

	if length != int(p.length) || numTransforms != len(p.transforms) {
		return false
	}
	p.raw = p.raw[:length]

	return true
}

// IKEv2 only
type transformV2 struct {
	raw           []byte
	lastTransform bool // 3 if more, 0 if last
	reserved1     uint8
	length        uint16
	transformType uint8
	reserved2     uint8
	transformId   uint16
	attributes    []*attribute
}

func (p *transformV2) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}

	x = make([]byte, 8)

	for _, attribute := range p.attributes {
		x = append(x, attribute.marshal()...)
	}

	if p.lastTransform {
		x[0] = uint8(0)
	} else {
		x[0] = uint8(3)
	}
	x[1] = p.reserved1
	x[2] = uint8(len(x) >> 8)
	x[3] = uint8(len(x))
	x[4] = uint8(p.transformType)
	x[5] = uint8(p.reserved2)
	x[6] = uint8(p.transformId >> 8)
	x[7] = uint8(p.transformId)

	return
}

func (p *transformV2) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)

	if len(data) < 8 {
		return false
	}

	if uint8(data[0]) == 0 {
		p.lastTransform = true
	} else {
		p.lastTransform = false
	}
	p.reserved1 = uint8(data[1])
	p.length = uint16(data[2])<<8 | uint16(data[3])
	p.transformType = uint8(data[4])
	p.reserved2 = uint8(data[5])
	p.transformId = uint16(data[6])<<8 | uint16(data[7])
	p.attributes = make([]*attribute, 0)

	data = data[8:]
	length := 8

	for len(data) > 0 && length < int(p.length) {
		a := new(attribute)
		if ok := a.unmarshal(data); !ok {
			return false
		} else {
			length += len(a.raw)
			data = data[len(a.raw):]
			p.attributes = append(p.attributes, a)
		}
	}

	if length != int(p.length) {
		return false
	}

	p.raw = p.raw[:length]

	return true
}

type payloadKeyExchangeV2 struct {
	raw             []byte
	dhGroup         uint16
	reserved        uint16
	keyExchangeData []byte
}

func (p *payloadKeyExchangeV2) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}
	x = make([]byte, 4)
	x[0] = uint8(p.dhGroup << 8)
	x[1] = uint8(p.dhGroup)
	x[2] = uint8(p.reserved << 8)
	x[3] = uint8(p.reserved)
	x = append(x, p.keyExchangeData...)
	return
}

func (p *payloadKeyExchangeV2) unmarshal(data []byte) bool {
	p.raw = data
	if len(data) < 4 {
		return false
	}

	p.dhGroup = uint16(data[0])<<8 | uint16(data[1])
	p.reserved = uint16(data[2])<<8 | uint16(data[3])
	p.keyExchangeData = data[4:]

	return true
}

type payloadKeyExchangeV1 struct {
	raw             []byte
	keyExchangeData []byte
}

func (p *payloadKeyExchangeV1) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}
	x = append(x, p.keyExchangeData...)
	return
}

func (p *payloadKeyExchangeV1) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)
	p.keyExchangeData = append(p.keyExchangeData, data...)
	return true
}

type payloadIdentification struct {
	raw      []byte
	idType   uint8
	reserved [3]byte
	idData   []byte
}

func (p *payloadIdentification) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}
	x = make([]byte, 4)
	x[0] = uint8(p.idType)
	copy(x[1:4], p.reserved[:])
	x = append(x, p.idData...)
	return
}

func (p *payloadIdentification) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)
	if len(data) < 4 {
		return false
	}
	p.idType = data[0]
	copy(p.reserved[:], data[1:4])
	p.idData = data[4:]
	return true
}

type payloadCertificate struct {
	raw             []byte
	encoding        uint8
	certificateData []byte //TODO: parse cert
}

func (p *payloadCertificate) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}
	x = make([]byte, 1)
	x[1] = p.encoding
	x = append(x, p.certificateData...)
	return
}

func (p *payloadCertificate) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)
	if len(data) < 1 {
		return false
	}
	p.encoding = uint8(data[0])
	p.certificateData = data[1:]
	return true
}

type payloadCertificateRequest struct {
	raw             []byte
	encoding        uint8
	certificateAuth []byte
}

func (p *payloadCertificateRequest) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}
	x = make([]byte, 1)
	x[1] = p.encoding
	x = append(x, p.certificateAuth...)
	return
}

func (p *payloadCertificateRequest) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)
	if len(data) < 1 {
		return false
	}
	p.encoding = uint8(data[0])
	p.certificateAuth = data[1:]
	return true
}

// not implemented
type payloadAuthentication struct {
	raw        []byte
	authMethod uint8
	reserved   uint32
	authData   []byte
}

// IKEv1 and IKEv2
type payloadNonce struct {
	raw       []byte
	nonceData []byte // 16-256 bytes
}

func (p *payloadNonce) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}
	x = append(x, p.nonceData...)
	return
}

func (p *payloadNonce) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)
	// validate nonce length
	//if len(data) < 16 || len(data) > 256 {
	//    return false
	//}
	p.nonceData = append(p.nonceData, data...)
	return true
}

// IKEv2 only
type payloadNotifyV2 struct {
	raw        []byte
	protocolId uint8
	notifyType uint16
	spi        []byte
	notifyData []byte
}

func (p *payloadNotifyV2) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}
	x = make([]byte, 4)
	x[0] = uint8(p.protocolId)
	x[1] = uint8(len(p.spi))
	x[2] = uint8(p.notifyType >> 8)
	x[3] = uint8(p.notifyType)
	x = append(x, p.spi...)
	x = append(x, p.notifyData...)
	return
}

func (p *payloadNotifyV2) unmarshal(data []byte) bool {
	p.raw = append([]byte{}, data...)
	if len(data) < 4 {
		return false
	}
	p.protocolId = uint8(data[0])
	p.notifyType = uint16(data[2])<<8 | uint16(data[3])
	if len(data) < 4+int(data[1]) {
		return false
	}
	p.spi = data[4 : 4+int(data[1])]
	p.notifyData = append([]byte{}, data[4+int(data[1]):]...)
	return true
}

// IKEv1 only
type payloadNotifyV1 struct {
	raw        []byte
	doi        uint32
	protocolId uint8
	notifyType uint16
	spi        []byte
	notifyData []byte
}

func (p *payloadNotifyV1) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}
	x = make([]byte, 8)
	x[0] = uint8(p.doi >> 24)
	x[1] = uint8(p.doi >> 16)
	x[2] = uint8(p.doi >> 8)
	x[3] = uint8(p.doi)
	x[4] = uint8(p.protocolId)
	x[5] = uint8(len(p.spi))
	x[6] = uint8(p.notifyType >> 8)
	x[7] = uint8(p.notifyType)
	x = append(x, p.spi...)
	x = append(x, p.notifyData...)
	return
}

func (p *payloadNotifyV1) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)
	if len(data) < 8 {
		return false
	}
	p.doi = uint32(data[0])<<24 |
		uint32(data[1])<<16 |
		uint32(data[2])<<8 |
		uint32(data[3])
	p.protocolId = uint8(data[4])
	p.notifyType = uint16(data[6])<<8 | uint16(data[7])
	if len(data) < 4+int(data[5]) {
		return false
	}
	p.spi = data[4 : 4+int(data[5])]
	p.notifyData = data[4+int(data[5]):]
	return true
}

type payloadHashV1 struct {
	raw      []byte
	hashData []byte
}

func (p *payloadHashV1) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}
	x = append(x, p.hashData...)
	return
}

func (p *payloadHashV1) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)
	p.hashData = append(p.hashData, data...)
	return true
}

// not implemented
type payloadDelete struct {
	raw     []byte
	spiSize uint8
	spiNum  uint16
	spis    []byte
}

// IKEv1 and IKEv2
type payloadVendorId struct {
	raw []byte
	id  []byte
}

func (p *payloadVendorId) marshal() (x []byte) {
	if p.raw != nil {
		return p.raw
	}
	x = append(x, p.id...)
	return
}

func (p *payloadVendorId) unmarshal(data []byte) bool {
	p.raw = append(p.raw, data...)
	p.id = append(p.id, data...)
	return true
}

// not implemented
type payloadTrafficSelector struct {
	raw []byte
}

// not implemented
type payloadEncrypted struct {
	raw []byte
}

// not implemented
type payloadConfiguration struct {
	raw []byte
}

// not implemented
type payloadEAP struct {
	raw []byte
}
