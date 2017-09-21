package ike

import (
	"encoding/json"
)

type HandshakeLog struct {
	// IKEv1 Main Mode
	InitiatorMainSA *IkeMessage `json:"initiator_main_sa,omitempty"`
	ResponderMainSA *IkeMessage `json:"responder_main_sa,omitempty"`
	InitiatorMainKE *IkeMessage `json:"initiator_main_ke,omitempty"`
	ResponderMainKE *IkeMessage `json:"responder_main_ke,omitempty"`

	// IKEv1 Aggressive Mode
	InitiatorAggressive *IkeMessage `json:"initiator_aggr,omitempty"`
	ResponderAggressive *IkeMessage `json:"responder_aggr,omitempty"`

	// IKEv2
	InitiatorSAInit *IkeMessage `json:"initiator_ike_sa_init,omitempty"`
	ResponderSAInit *IkeMessage `json:"responder_ike_sa_init,omitempty"`

	// All
	ErrorNotification *IkeMessage   `json:"error_notification,omitempty"`
	Unexpected        []*IkeMessage `json:"unexpected_messages,omitempty"`
}

type IkeMessage struct {
	Raw          []byte
	InitiatorSPI []byte
	ResponderSPI []byte
	Payloads     []Payload
}

func (msg *IkeMessage) MarshalJSON() ([]byte, error) {
	aux := []interface{}{}

	for _, p := range msg.Payloads {
		// IKEv1 or IKEv2
		if pa, ok := p.(*SecurityAssociation); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*KeyExchange); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*Identification); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*Nonce); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*VendorId); ok {
			aux = append(aux, *pa)
		}
		if pa, ok := p.(*Notify); ok {
			aux = append(aux, *pa)
		}
		/*
		   if pa, ok := p.(*Certificate); ok {
		       aux = append(aux, *pa)
		   }
		   if pa, ok := p.(*CertificateRequest); ok {
		       aux = append(aux, *pa)
		   }
		*/
	}

	aux2 := struct {
		Raw          []byte        `json:"raw,omitempty"`
		InitiatorSPI []byte        `json:"initiator_spi,omitempty"`
		ResponderSPI []byte        `json:"responder_spi,omitempty"`
		Proposals    []interface{} `json:"payloads,omitempty"`
	}{
		Raw:          msg.Raw,
		InitiatorSPI: msg.InitiatorSPI,
		ResponderSPI: msg.ResponderSPI,
		Proposals:    aux,
	}
	return json.Marshal(&aux2)
}

type Payload interface{}

func (msg *ikeMessage) MakeLog() (m *IkeMessage) {
	m = new(IkeMessage)
	m.InitiatorSPI = append([]byte{}, msg.hdr.initiatorSPI[:]...)
	m.ResponderSPI = append([]byte{}, msg.hdr.responderSPI[:]...)
	m.Raw = append(m.Raw, msg.marshal()...)
	for _, payload := range msg.payloads {
		m.Payloads = append(m.Payloads, payload.MakeLog())
	}
	return
}

func (p *payload) MakeLog() Payload {

	switch p.payloadType {
	case NO_NEXT_PAYLOAD:
		return new(EmptyPayload)
		//  IKEv1
	case SECURITY_ASSOCIATION_V1:
		if pa, ok := p.body.(*payloadSecurityAssociationV1); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case KEY_EXCHANGE_V1:
		if pa, ok := p.body.(*payloadKeyExchangeV1); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case IDENTIFICATION_V1:
		if pa, ok := p.body.(*payloadIdentification); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	/*
	   case CERTIFICATE_V1:
	       if pa, ok := p.body.(*payloadCertificate); !ok {
	           return new(EmptyPayload)
	       } else {
	           return pa.MakeLog()
	       }
	   case CERTIFICATE_REQUEST_V1:
	       if pa, ok := p.body.(*payloadCertificateRequest); !ok {
	           return new(EmptyPayload)
	       } else {
	           return pa.MakeLog()
	       }
	   case HASH_V1:
	   case SIGNATURE_V1:
	*/
	case NONCE_V1:
		if pa, ok := p.body.(*payloadNonce); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case NOTIFICATION_V1:
		if pa, ok := p.body.(*payloadNotifyV1); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	/*
	   case DELETE_V1:
	*/
	case VENDOR_ID_V1:
		if pa, ok := p.body.(*payloadVendorId); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
		//  IKEv2
	case SECURITY_ASSOCIATION_V2:
		if pa, ok := p.body.(*payloadSecurityAssociationV2); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case KEY_EXCHANGE_V2:
		if pa, ok := p.body.(*payloadKeyExchangeV2); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case IDENTIFICATION_INITIATOR_V2:
		if pa, ok := p.body.(*payloadIdentification); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case IDENTIFICATION_RESPONDER_V2:
		if pa, ok := p.body.(*payloadIdentification); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	/*
	   case CERTIFICATE_V2:
	       if pa, ok := p.body.(*payloadCertificate); !ok {
	           return new(EmptyPayload)
	       } else {
	           return pa.MakeLog()
	       }
	   case CERTIFICATE_REQUEST_V2:
	       if pa, ok := p.body.(*payloadCertificateRequest); !ok {
	           return new(EmptyPayload)
	       } else {
	           return pa.MakeLog()
	       }
	   case AUTHENTICATION_V2:
	*/
	case NONCE_V2:
		if pa, ok := p.body.(*payloadNonce); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	case NOTIFY_V2:
		if pa, ok := p.body.(*payloadNotifyV2); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	/*
	   case DELETE_V2:
	*/
	case VENDOR_ID_V2:
		if pa, ok := p.body.(*payloadVendorId); !ok {
			return new(EmptyPayload)
		} else {
			return pa.MakeLog()
		}
	}
	return new(EmptyPayload)
}

type EmptyPayload struct {
	Name string `json:"type"`
}

type SecurityAssociation struct {
	Name      string     `json:"type,omitempty"`
	Raw       []byte     `json:"raw,omitempty"`
	Doi       uint32     `json:"doi,omitempty"`
	Situation []byte     `json:"situation,omitempty"`
	Proposals []Proposal `json:"proposals,omitempty"`
}

func (p *payloadSecurityAssociationV2) MakeLog() *SecurityAssociation {
	sa := new(SecurityAssociation)
	//sa.Raw = append(sa.Raw, p.marshal()...)

	sa.Proposals = make([]Proposal, len(p.proposals))
	for proposalidx, proposal := range p.proposals {
		sa.Proposals[proposalidx].Raw = append(sa.Proposals[proposalidx].Raw, proposal.raw...)
		sa.Proposals[proposalidx].ProposalNum = proposal.proposalNum
		sa.Proposals[proposalidx].ProtocolId = proposal.protocolId
		sa.Proposals[proposalidx].Spi = append(sa.Proposals[proposalidx].Spi, proposal.spi...)
		sa.Proposals[proposalidx].Transforms = make([]Transform, len(proposal.transforms))
		for transformidx, transform := range proposal.transforms {
			sa.Proposals[proposalidx].Transforms[transformidx].Raw = append(sa.Proposals[proposalidx].Transforms[transformidx].Raw, transform.raw...)
			sa.Proposals[proposalidx].Transforms[transformidx].Type = transform.transformType
			sa.Proposals[proposalidx].Transforms[transformidx].Id = transform.transformId
			sa.Proposals[proposalidx].Transforms[transformidx].Attributes = make([]Attribute, len(transform.attributes))
			for attributeidx, attribute := range transform.attributes {
				sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Raw = append(sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Raw, attribute.raw...)
				sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Type = attribute.attributeType
				sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Value = append(sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Value, attribute.attributeValue...)
			}
		}
	}

	sa.Name = "security_association"
	return sa
}

func (p *payloadSecurityAssociationV1) MakeLog() *SecurityAssociation {
	sa := new(SecurityAssociation)
	//sa.Raw = append(sa.Raw, p.marshal()...)
	sa.Doi = p.doi
	sa.Situation = append(sa.Situation, p.situation...)

	sa.Proposals = make([]Proposal, len(p.proposals))
	for proposalidx, proposal := range p.proposals {
		sa.Proposals[proposalidx].Raw = append(sa.Proposals[proposalidx].Raw, proposal.raw...)
		sa.Proposals[proposalidx].ProposalNum = proposal.proposalNum
		sa.Proposals[proposalidx].ProtocolId = proposal.protocolId
		sa.Proposals[proposalidx].Spi = append(sa.Proposals[proposalidx].Spi, proposal.spi...)
		sa.Proposals[proposalidx].Transforms = make([]Transform, len(proposal.transforms))
		for transformidx, transform := range proposal.transforms {
			sa.Proposals[proposalidx].Transforms[transformidx].Raw = append(sa.Proposals[proposalidx].Transforms[transformidx].Raw, transform.raw...)
			sa.Proposals[proposalidx].Transforms[transformidx].Num = transform.transformNum
			sa.Proposals[proposalidx].Transforms[transformidx].IdV1 = transform.transformId
			sa.Proposals[proposalidx].Transforms[transformidx].Attributes = make([]Attribute, len(transform.attributes))
			for attributeidx, attribute := range transform.attributes {
				sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Raw = append(sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Raw, attribute.raw...)
				sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Type = attribute.attributeType
				sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Value = append(sa.Proposals[proposalidx].Transforms[transformidx].Attributes[attributeidx].Value, attribute.attributeValue...)
			}
		}
	}

	sa.Name = "security_association"
	return sa
}

type KeyExchange struct {
	Name            string `json:"type,omitempty"`
	Raw             []byte `json:"raw,omitempty"`
	DhGroup         uint16 `json:"dh_group,omitempty"`
	KeyExchangeData []byte `json:"kex_data,omitempty"`
}

func (p *payloadKeyExchangeV1) MakeLog() *KeyExchange {
	ke := new(KeyExchange)
	//ke.Raw = append(ke.Raw, p.marshal()...)
	//ke.DhGroup = p.dhGroup
	ke.KeyExchangeData = append(ke.KeyExchangeData, p.keyExchangeData...)
	ke.Name = "key_exchange"
	return ke
}

func (p *payloadKeyExchangeV2) MakeLog() *KeyExchange {
	ke := new(KeyExchange)
	//ke.Raw = append(ke.Raw, p.marshal()...)
	ke.DhGroup = p.dhGroup
	ke.KeyExchangeData = append(ke.KeyExchangeData, p.keyExchangeData...)
	ke.Name = "key_exchange"
	return ke
}

type Nonce struct {
	Name      string `json:"type,omitempty"`
	Raw       []byte `json:"raw,omitempty"`
	NonceData []byte `json:"nonce,omitempty"`
}

func (p *payloadNonce) MakeLog() *Nonce {
	no := new(Nonce)
	// no.Raw = append(no.Raw, p.marshal()...)
	no.NonceData = append(no.NonceData, p.nonceData...)
	no.Name = "nonce"
	return no
}

type VendorId struct {
	Name  string `json:"type,omitempty"`
	Raw   []byte `json:"raw,omitempty"`
	Id    []byte `json:"id,omitempty"`
	IdStr string `json:"id_string,omitempty"`
}

func (p *payloadVendorId) MakeLog() *VendorId {
	vi := new(VendorId)
	// vi.Raw = append(.Raw, p.marshal()...)
	vi.Id = append(vi.Id, p.id...)
	vi.IdStr = lookupVendorId(vi.Id)
	vi.Name = "vendor_id"
	return vi
}

type Identification struct {
	Name   string `json:"type,omitempty"`
	Raw    []byte `json:"raw,omitempty"`
	IdType uint8  `json:"id,omitempty"`
	IdData []byte `json:"id_string,omitempty"`
}

func (p *payloadIdentification) MakeLog() *Identification {
	id := new(Identification)
	// vi.Raw = append(.Raw, p.marshal()...)
	id.IdType = p.idType
	id.IdData = append(id.IdData, p.idData...)
	id.Name = "identification"
	return id
}

type Notify struct {
	Name       string `json:"type,omitempty"`
	Raw        []byte `json:"raw,omitempty"`
	Doi        uint32 `json:"doi,omitempty"`
	ProtocolId uint8  `json:"protocol_id,omitempty"`
	NotifyType uint16 `json:"notify_type,omitempty"`
	Spi        []byte `json:"spi,omitempty"`
	NotifyData []byte `json:"notify_data,omitempty"`
}

func (p *payloadNotifyV1) MakeLog() *Notify {
	n := new(Notify)
	// n.Raw = append(n.Raw, p.marshal()...)
	n.Doi = p.doi
	n.ProtocolId = p.protocolId
	n.NotifyType = p.notifyType
	n.Spi = append(n.Spi, p.spi...)
	n.NotifyData = append(n.NotifyData, p.notifyData...)
	n.Name = "notification"
	return n
}

func (p *payloadNotifyV2) MakeLog() *Notify {
	n := new(Notify)
	// n.Raw = append(n.Raw, p.marshal()...)
	n.ProtocolId = p.protocolId
	n.NotifyType = p.notifyType
	n.Spi = append(n.Spi, p.spi...)
	n.NotifyData = append(n.NotifyData, p.notifyData...)
	n.Name = "notification"
	return n
}
