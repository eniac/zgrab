package ike

import (
    "github.com/zmap/zgrab/ztools/zlog"
    "errors"
    "bytes"
)

func (c *Conn) InitiatorHandshake() (err error) {
    c.handshakeLog = new(HandshakeLog)

    if _, err := c.config.getRandom().Read(c.initiatorSPI[:]); err != nil {
        zlog.Fatalf("unable to read from random")
    }

    if c.config.Version == VersionIKEv2 {
        return c.InitiatorHandshakeV2()
    }
    if c.config.Version == VersionIKEv1 {
        if c.config.ExchangeType == IDENTITY_PROTECTION_V1 {
            return c.InitiatorHandshakeMain()
        }
        if c.config.ExchangeType == AGGRESSIVE_V1 {
            return c.InitiatorHandshakeAggressive()
        }
    }
    return errors.New("invalid config")
}

func (c *Conn) InitiatorHandshakeMain() (err error) {
    // Send IKEv1 Main Mode SA message
    msg := c.buildInitiatorMainSA()
    if err = c.writeMessage(msg); err != nil {
        return
    }
    c.handshakeLog.InitiatorMainSA = msg.MakeLog()

    var response *ikeMessage

    // Messages can come in any order and be retransmitted, so expect anything
    for c.handshakeLog.ResponderMainSA == nil {

        // Read response
        response, err = c.readMessage()
        if err != nil {
            return
        }
        log := response.MakeLog()

        // Check if response contains an error notification and abort. Many implementations have invalid SPIs for this, so put it before the SPI check.
        if err = response.containsErrorNotification(); err != nil {
            c.handshakeLog.ErrorNotification = response.MakeLog()
            return
        }

        // Verify that the SPI is correct. This could occur if we have two simultaneous connections with the host, so don't treat this as an error.
        if ! bytes.Equal(c.initiatorSPI[:], response.hdr.initiatorSPI[:]) {
            c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
            //err = errors.New("invalid initiator SPI")
            continue
        }
        if ! bytes.Equal(c.responderSPI[:], make([]byte, 8)) && ! bytes.Equal(c.responderSPI[:], response.hdr.responderSPI[:]) {
            c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
            //err = errors.New("invalid responder SPI")
            continue
        }

        if response.containsPayload(SECURITY_ASSOCIATION_V1) {
            if c.handshakeLog.ResponderMainSA == nil {
                c.handshakeLog.ResponderMainSA = log
                copy(c.responderSPI[:], response.hdr.responderSPI[:])
                c.config.DhGroup = response.getResponderDhGroup()
                if c.config.DhGroup == 0 {
                    err = errors.New("Unable to extract Diffie-Hellman group from responser Security Exchange")
                    return
                }

                if _, ok := groupMapV1[c.config.DhGroup]; !ok {
                    err = errors.New("Unsupported Diffie-Hellman group in responder Security Association")
                    return
                }

            } else if bytes.Equal(log.Raw, c.handshakeLog.ResponderMainSA.Raw) {
                // ignore retransmissions
            } else {
                // they sent two different SA messages back, which is unexpected
                c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
            }
            continue
        }

        if response.containsPayload(KEY_EXCHANGE_V1) && response.containsPayload(NONCE_V1) {
            log := response.MakeLog()
            if c.handshakeLog.ResponderMainKE == nil {
                // They sent a KE message before we did. Does not follow the RFC, but OK.
                c.handshakeLog.ResponderMainKE = log
            } else if bytes.Equal(log.Raw, c.handshakeLog.ResponderMainKE.Raw) {
                // ignore retransmissions
            } else {
                // they sent two different KE messages back, which is unexpected
                c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
            }
            continue
        }

        // unexpected message
        c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
    }

    // Build IKEv1 Main Mode KE message
    msg = c.buildInitiatorMainKE()
    if err = c.writeMessage(msg); err != nil {
        return
    }
    c.handshakeLog.InitiatorMainKE = msg.MakeLog()

    // Messages can come in any order and be retransmitted, so expect anything
    for c.handshakeLog.ResponderMainKE == nil {

        // Read response
        response, err = c.readMessage()
        if err != nil {
            return
        }
        log := response.MakeLog()

        // Check if response contains an error notification and abort. Many implementations have invalid SPIs for this, so put it before the SPI check.
        if err = response.containsErrorNotification(); err != nil {
            c.handshakeLog.ErrorNotification = response.MakeLog()
            return
        }

        // Verify that the SPI is correct. This could occur if we have two simultaneous connections with the host, so don't treat this as an error.
        if ! bytes.Equal(c.initiatorSPI[:], response.hdr.initiatorSPI[:]) {
            c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
            //err = errors.New("invalid initiator SPI")
            continue
        }
        if ! bytes.Equal(c.responderSPI[:], make([]byte, 8)) && ! bytes.Equal(c.responderSPI[:], response.hdr.responderSPI[:]) {
            c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
            //err = errors.New("invalid responder SPI")
            continue
        }

        if response.containsPayload(SECURITY_ASSOCIATION_V1) {
            if c.handshakeLog.ResponderMainSA == nil {
                zlog.Fatalf("execution error: c.handshakeLog.ResponderMainSA should not be nil")
            } else if bytes.Equal(log.Raw, c.handshakeLog.ResponderMainSA.Raw) {
                // ignore retransmissions
            } else {
                // they sent two different SA messages back, which is unexpected
                c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
            }
            continue
        }

        if response.containsPayload(KEY_EXCHANGE_V1) && response.containsPayload(NONCE_V1) {
            if c.handshakeLog.ResponderMainKE == nil {
                // They sent a KE message before we did. Does not follow the RFC, but OK.
                c.handshakeLog.ResponderMainKE = log
            } else if bytes.Equal(log.Raw, c.handshakeLog.ResponderMainKE.Raw) {
                // ignore retransmissions
            } else {
                // they sent two different KE messages back, which is unexpected
                c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
            }
            continue
        }
        // unexpected message
        c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
    }

    // TODO: HASH_I and HASH_R messages
    return
}

func (c *Conn) buildInitiatorMainSA() (msg *ikeMessage) {
    msg = new(ikeMessage)
    msg.hdr = new(ikeHeader)
    copy(msg.hdr.initiatorSPI[:], c.initiatorSPI[:])
    // msg.hdr.responderSPI
    msg.hdr.nextPayload      = SECURITY_ASSOCIATION_V1
    msg.hdr.majorVersion     = VersionIKEv1
    msg.hdr.minorVersion     = 0
    msg.hdr.exchangeType     = IDENTITY_PROTECTION_V1
    msg.hdr.flags            = 0
    msg.hdr.messageId        = 0 // Message ID
    msg.hdr.length           = IKE_HEADER_LEN // header + body

    // add payloads
    payload1 := c.buildPayload(SECURITY_ASSOCIATION_V1)
    payload1.nextPayload = NO_NEXT_PAYLOAD
    msg.hdr.length += uint32(payload1.length)
    msg.payloads = append(msg.payloads, payload1)

    return
}

func (c *Conn) buildInitiatorMainKE() (msg *ikeMessage) {
    msg = new(ikeMessage)
    msg.hdr = new(ikeHeader)
    if c.handshakeLog.InitiatorMainSA == nil || c.handshakeLog.ResponderMainSA == nil {
        return
    }
    copy(msg.hdr.initiatorSPI[:], c.initiatorSPI[:])
    copy(msg.hdr.responderSPI[:], c.responderSPI[:])
    msg.hdr.nextPayload      = KEY_EXCHANGE_V1
    msg.hdr.majorVersion     = VersionIKEv1
    msg.hdr.minorVersion     = 0
    msg.hdr.exchangeType     = IDENTITY_PROTECTION_V1
    msg.hdr.flags            = 0
    msg.hdr.messageId        = 0 // Message ID
    msg.hdr.length           = IKE_HEADER_LEN // header + body

    // add payloads
    payload1 := c.buildPayload(KEY_EXCHANGE_V1)
    payload1.nextPayload = NONCE_V1
    msg.hdr.length += uint32(payload1.length)
    msg.payloads = append(msg.payloads, payload1)

    payload2 := c.buildPayload(NONCE_V1)
    payload2.nextPayload = NO_NEXT_PAYLOAD
    msg.hdr.length += uint32(payload2.length)
    msg.payloads = append(msg.payloads, payload2)

    return
}

func (c *Conn) InitiatorHandshakeAggressive() (err error) {

    // Send IKEv1 Aggressive Mode message
    msg := c.buildInitiatorAggressive()
    if err = c.writeMessage(msg); err != nil {
        return
    }
    c.handshakeLog.InitiatorAggressive = msg.MakeLog()

    var response *ikeMessage

    // Messages can come in any order and be retransmitted, so expect anything
    for c.handshakeLog.ResponderAggressive == nil {

        // Read response
        response, err = c.readMessage()
        if err != nil {
            return
        }
        log := response.MakeLog()

        // Check if response contains an error notification and abort. Many implementations have invalid SPIs for this, so put it before the SPI check.
        if err = response.containsErrorNotification(); err != nil {
            c.handshakeLog.ErrorNotification = response.MakeLog()
            return
        }

        // Verify that the SPI is correct. This could occur if we have two simultaneous connections with the host, so don't treat this as an error.
        if ! bytes.Equal(c.initiatorSPI[:], response.hdr.initiatorSPI[:]) {
            c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
            //err = errors.New("invalid initiator SPI")
            continue
        }
        if ! bytes.Equal(c.responderSPI[:], make([]byte, 8)) && ! bytes.Equal(c.responderSPI[:], response.hdr.responderSPI[:]) {
            c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
            //err = errors.New("invalid responder SPI")
            continue
        }

        if response.containsPayload(SECURITY_ASSOCIATION_V1) && response.containsPayload(KEY_EXCHANGE_V1) {
            c.handshakeLog.ResponderAggressive = log
            continue
        }

        // unexpected message
        c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
    }
    return
}

func (c *Conn) buildInitiatorAggressive() (msg *ikeMessage) {
    msg = new(ikeMessage)
    msg.hdr = new(ikeHeader)
    copy(msg.hdr.initiatorSPI[:], c.initiatorSPI[:])
    // msg.hdr.responderSPI
    msg.hdr.nextPayload      = SECURITY_ASSOCIATION_V1
    msg.hdr.majorVersion     = VersionIKEv1
    msg.hdr.minorVersion     = 0
    msg.hdr.exchangeType     = AGGRESSIVE_V1
    msg.hdr.flags            = 0
    msg.hdr.messageId        = 0 // Message ID
    msg.hdr.length           = IKE_HEADER_LEN // header + body

    // add payloads
    payload1 := c.buildPayload(SECURITY_ASSOCIATION_V1)
    payload1.nextPayload = KEY_EXCHANGE_V1
    msg.hdr.length += uint32(payload1.length)
    msg.payloads = append(msg.payloads, payload1)

    payload2 := c.buildPayload(KEY_EXCHANGE_V1)
    payload2.nextPayload = NONCE_V1
    msg.hdr.length += uint32(payload2.length)
    msg.payloads = append(msg.payloads, payload2)

    payload3 := c.buildPayload(NONCE_V1)
    payload3.nextPayload = IDENTIFICATION_V1
    msg.hdr.length += uint32(payload3.length)
    msg.payloads = append(msg.payloads, payload3)

    payload4 := c.buildPayload(IDENTIFICATION_V1)
    payload4.nextPayload = NO_NEXT_PAYLOAD
    msg.hdr.length += uint32(payload4.length)
    msg.payloads = append(msg.payloads, payload4)

    return
}

func (c *Conn) InitiatorHandshakeV2() (err error) {

    // Send IKE_SA_INIT
    msg := c.buildInitiatorSAInit()
    if err = c.writeMessage(msg); err != nil {
        return
    }
    c.handshakeLog.InitiatorSAInit = msg.MakeLog()

    var response *ikeMessage

    // Messages can come in any order and be retransmitted, so expect anything
    for c.handshakeLog.ResponderSAInit == nil {

        // Read response
        response, err = c.readMessage()
        if err != nil {
            return
        }
        log := response.MakeLog()

        // Check if response contains an INVALID_KE_PAYLOAD request. If so, initiate another handshake with the requested group.
        if dhGroup := response.containsInvalidKEPayload(); dhGroup != 0 {
            c.config.DhGroup = dhGroup
            return c.InitiatorHandshakeV2()
        }

        // Check if response contains an error notification and abort. Many implementations have invalid SPIs for this, so put it before the SPI check.
        if err = response.containsErrorNotification(); err != nil {
            c.handshakeLog.ErrorNotification = response.MakeLog()
            return
        }

        // Verify that the SPI is correct. This could occur if we have two simultaneous connections with the host, so don't treat this as an error.
        if ! bytes.Equal(c.initiatorSPI[:], response.hdr.initiatorSPI[:]) {
            c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
            //err = errors.New("invalid initiator SPI")
            continue
        }
        if ! bytes.Equal(c.responderSPI[:], make([]byte, 8)) && ! bytes.Equal(c.responderSPI[:], response.hdr.responderSPI[:]) {
            c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
            //err = errors.New("invalid responder SPI")
            continue
        }

        if response.containsPayload(SECURITY_ASSOCIATION_V2) && response.containsPayload(KEY_EXCHANGE_V2) {
            c.handshakeLog.ResponderSAInit = log
            continue
        }

        // unexpected message
        c.handshakeLog.Unexpected = append(c.handshakeLog.Unexpected, log)
    }
	return
}

func (c *Conn) buildInitiatorSAInit() (msg *ikeMessage) {
    msg = new(ikeMessage)
    msg.hdr = new(ikeHeader)
    copy(msg.hdr.initiatorSPI[:], c.initiatorSPI[:])
    // msg.hdr.responderSPI
    msg.hdr.nextPayload      = SECURITY_ASSOCIATION_V2
    msg.hdr.majorVersion     = VersionIKEv2
    msg.hdr.minorVersion     = 0
    msg.hdr.exchangeType     = IKE_SA_INIT_V2
    msg.hdr.flags            = 0x08 // flags (bit 3 set)
    msg.hdr.messageId        = 0 // Message ID
    msg.hdr.length           = IKE_HEADER_LEN // header + body

    // add payloads
    payload1 := c.buildPayload(SECURITY_ASSOCIATION_V2)
    payload1.nextPayload = KEY_EXCHANGE_V2
    msg.hdr.length += uint32(payload1.length)
    msg.payloads = append(msg.payloads, payload1)

    payload2 := c.buildPayload(KEY_EXCHANGE_V2)
    payload2.nextPayload = NONCE_V2
    msg.hdr.length += uint32(payload2.length)
    msg.payloads = append(msg.payloads, payload2)

    payload3 := c.buildPayload(NONCE_V2)
    payload3.nextPayload = NO_NEXT_PAYLOAD
    msg.hdr.length += uint32(payload3.length)
    msg.payloads = append(msg.payloads, payload3)

    return
}

func (c *Conn) buildPayload(payloadType uint8) (p *payload) {
    p = new(payload)
    p.payloadType = payloadType

    switch payloadType {
    //  IKEv1
    case SECURITY_ASSOCIATION_V1:
        p.body = c.buildPayloadSecurityAssociationV1()
    case KEY_EXCHANGE_V1:
        p.body = c.buildPayloadKeyExchangeV1()
    case IDENTIFICATION_V1:
        p.body = c.buildPayloadIdentificationV1()
    case CERTIFICATE_V1:
    case CERTIFICATE_REQUEST_V1:
    case HASH_V1:
    case SIGNATURE_V1:
    case NONCE_V1:
        p.body = c.buildPayloadNonce()
    case NOTIFICATION_V1:
    case DELETE_V1:
    case VENDOR_ID_V1:
        p.body = c.buildPayloadVendorId()
    //  IKEv2
    case SECURITY_ASSOCIATION_V2:
        p.body = c.buildPayloadSecurityAssociationV2()
    case KEY_EXCHANGE_V2:
        p.body = c.buildPayloadKeyExchangeV2()
    case IDENTIFICATION_INITIATOR_V2:
    case IDENTIFICATION_RESPONDER_V2:
    case CERTIFICATE_V2:
    case CERTIFICATE_REQUEST_V2:
    case AUTHENTICATION_V2:
    case NONCE_V2:
        p.body = c.buildPayloadNonce()
    case NOTIFY_V2:
    case DELETE_V2:
    case VENDOR_ID_V2:
        p.body = c.buildPayloadVendorId()
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

func (c *Conn) buildPayloadSecurityAssociationV1() (p *payloadSecurityAssociationV1) {
    p = new(payloadSecurityAssociationV1)
    p.doi = IPSEC_V1
    // situation is a bitmask
    sit := SIT_IDENTITY_ONLY_V1
    p.situation = make([]byte, 4)
    p.situation[0] = uint8(sit >> 24)
    p.situation[1] = uint8(sit >> 16)
    p.situation[2] = uint8(sit >> 8)
    p.situation[3] = uint8(sit)
    for _, proposalConfig := range(c.config.Proposals) {
        p.proposals = append(p.proposals, buildProposalV1(proposalConfig))
    }
    if len(p.proposals) > 0 {
        p.proposals[len(p.proposals)-1].lastProposal = true
    }
    return p
}

func buildTransformV1(transformConfig TransformConfig) (t *transformV1) {
    t = new(transformV1)
    t.lastTransform = false
    t.transformNum = transformConfig.TransformNum
    t.length = 8
    t.transformId = transformConfig.IdV1
    for _, attributeConfig := range(transformConfig.Attributes) {
        a := buildAttribute(attributeConfig)
        t.attributes = append(t.attributes, a)
        t.length += uint16(len(a.marshal()))
    }
    return
}

func buildProposalV1(proposalConfig ProposalConfig) (p* proposalV1) {
    p = new(proposalV1)
    p.protocolId = PROTO_ISAKMP_V1
    p.proposalNum = proposalConfig.ProposalNum
    p.lastProposal = false
    p.spi = []byte{}

    for _, transformConfig := range(proposalConfig.Transforms) {
        t := buildTransformV1(transformConfig)
        p.transforms = append(p.transforms, t)
        p.length += t.length
    }
    return
}

func (c *Conn) buildPayloadSecurityAssociationV2() (p *payloadSecurityAssociationV2) {
    p = new(payloadSecurityAssociationV2)
    for _, proposalConfig := range(c.config.Proposals) {
        p.proposals = append(p.proposals, buildProposalV2(proposalConfig))
    }
    if len(p.proposals) > 0 {
        p.proposals[len(p.proposals)-1].lastProposal = true
    }
    return p
}

func buildProposalV2(proposalConfig ProposalConfig) (p* proposalV2) {
    p = new(proposalV2)
    p.protocolId = IKE_V2
    p.proposalNum = proposalConfig.ProposalNum
    p.lastProposal = false
    p.spi = []byte{}

    for _, transformConfig := range(proposalConfig.Transforms) {
        t := buildTransformV2(transformConfig)
        p.transforms = append(p.transforms, t)
        p.length += t.length
    }
    return
}

func buildTransformV2(transformConfig TransformConfig) (t *transformV2) {
    t = new(transformV2)
    t.lastTransform = false
    t.transformType = transformConfig.Type
    t.length = 8
    t.transformId = transformConfig.Id
    for _, attributeConfig := range(transformConfig.Attributes) {
        a := buildAttribute(attributeConfig)
        t.attributes = append(t.attributes, a)
        t.length += uint16(len(a.marshal()))
    }
    return
}

func buildAttribute(attributeConfig AttributeConfig) (a *attribute) {
    a = new(attribute)
    a.attributeType = attributeConfig.Type
    a.attributeValue = make([]byte, len(attributeConfig.Value))
    copy(a.attributeValue, attributeConfig.Value)
    return
}

func (c *Conn) buildPayloadKeyExchangeV1() (p *payloadKeyExchangeV1) {
    p = new(payloadKeyExchangeV1)
    if c.config.KexValue != nil {
        p.keyExchangeData = append(p.keyExchangeData, c.config.KexValue...)
        return
    }
    if val, ok := groupMapV1[c.config.DhGroup]; ok {
        p.keyExchangeData = append(p.keyExchangeData, val...)
    } else {
        zlog.Fatalf("unsupported group: %d", c.config.DhGroup)
    }
    return
}

func (c *Conn) buildPayloadKeyExchangeV2() (p *payloadKeyExchangeV2) {
    p = new(payloadKeyExchangeV2)
    p.dhGroup = c.config.DhGroup
    if c.config.KexValue != nil {
        p.keyExchangeData = append(p.keyExchangeData, c.config.KexValue...)
        return
    }
    if val, ok := groupMapV2[c.config.DhGroup]; ok {
        p.keyExchangeData = append(p.keyExchangeData, val...)
    } else {
        zlog.Fatalf("unsupported group: %d", p.dhGroup)
    }
    return
}

func (c *Conn) buildPayloadNonce() (p *payloadNonce) {
    p = new(payloadNonce)
    // 96-byte nonce
    p.nonceData = append(p.nonceData, []byte("d3a261126ee5367a480154a1a1a3")...)
    p.nonceData = append(p.nonceData, []byte("f86ddd9e9c271cca03b413b8762c3648")...)
    p.nonceData = append(p.nonceData, []byte("f86ddd9e9c271cca03b413b8762c3648")...)
    p.nonceData = append(p.nonceData, []byte("9bc9")...)
    return
}

func (c *Conn) buildPayloadIdentificationV1() (p *payloadIdentification) {
    p = new(payloadIdentification)
    p.idType = ID_USER_FQDN_V1
    p.idData = []byte{}
    return
}

func (c *Conn) buildPayloadVendorId() (p *payloadVendorId) {
    p = new(payloadVendorId)
    return
}
