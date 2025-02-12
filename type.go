package golang_tls3

import "errors"

type ProtocolVersion uint16

func (p *ProtocolVersion) Marshal() []byte {
	var res [2]byte
	res[0] = byte(*p >> 8)
	res[1] = byte(*p & 0xff)
	return res[:]
}

func (p *ProtocolVersion) UnMarshal(data []byte) error {
	if len(data) != 2 {
		return errors.New("")
	}
	*p = ProtocolVersion(uint16(data[0])<<8 | uint16(data[1]))
	return nil
}

type Random [32]byte
type CipherSuite [2]uint8

type MessageType uint8

const (
	ClientHello         MessageType = 1
	ServerHello         MessageType = 2
	NewSessionTicket    MessageType = 4
	EndOfEarlyData      MessageType = 5
	EncryptedExtensions MessageType = 8
	Certificate         MessageType = 11
	CertificateRequest  MessageType = 13
	CertificateVerify   MessageType = 15
	Finished            MessageType = 20
	KeyUpdate           MessageType = 24
	MessageHash         MessageType = 254
)

type ExtensionType uint16

const (
	ServerName                          ExtensionType = 0  // RFC6066
	MaxFragmentLength                   ExtensionType = 1  // RFC6066
	StatusRequest                       ExtensionType = 5  // RFC6066
	SupportedGroups                     ExtensionType = 10 // RFC8422,7919
	SignatureAlgorithms                 ExtensionType = 13 // RFC8446
	UseSrtp                             ExtensionType = 14 // RFC5764
	Heartbeat                           ExtensionType = 15 // RFC6520
	ApplicationLayerProtocolNegotiation ExtensionType = 16 // RFC7301
	SignedCertificateTimestamp          ExtensionType = 18 // RFC6962
	ClientCertificateType               ExtensionType = 19 // RFC7250
	ServerCertificateType               ExtensionType = 20 // RFC7250
	Padding                             ExtensionType = 21 // RFC7685
	PreSharedKey                        ExtensionType = 41 // RFC8446  must last
	EarlyData                           ExtensionType = 42 // RFC8446
	SupportedVersions                   ExtensionType = 43 // RFC8446
	Cookie                              ExtensionType = 44 // RFC8446
	PSKKeyExchangeModes                 ExtensionType = 45 // RFC8446
	CertificateAuthorities              ExtensionType = 47 // RFC8446
	OidFilters                          ExtensionType = 48 // RFC8446
	PostHandshakeAuth                   ExtensionType = 49 // RFC8446
	SignatureAlgorithmsCert             ExtensionType = 50 // RFC8446
	KeyShare                            ExtensionType = 51 // RFC8446
)

type SignatureScheme uint16

const (
	RSA_PKCS1_SHA256 SignatureScheme = 0x0401
	RSA_PKCS1_SHA384 SignatureScheme = 0x0501
	RSA_PKCS1_SHA512 SignatureScheme = 0x0601

	ECDSA_SECP256R1_SHA256 SignatureScheme = 0x0403
	ECDSA_SECP384R1_SHA384 SignatureScheme = 0x0503
	ECDSA_SECP521R1_SHA512 SignatureScheme = 0x0603

	RSA_PSS_RSAE_SHA256 SignatureScheme = 0x0804
	RSA_PSS_RSAE_SHA384 SignatureScheme = 0x0805
	RSA_PSS_RSAE_SHA512 SignatureScheme = 0x0806

	EDDSA_ED25519 SignatureScheme = 0x0807
	EDDSA_ED448   SignatureScheme = 0x0808

	RSA_PSS_PSS_SHA256 SignatureScheme = 0x0809
	RSA_PSS_PSS_SHA384 SignatureScheme = 0x080a
	RSA_PSS_PSS_SHA512 SignatureScheme = 0x080b

	RSA_PKCS1_SHA1 SignatureScheme = 0x0201
	ECDSA_SHA1     SignatureScheme = 0x0203

	PRIVATE_USE SignatureScheme = 0xFFFF
)
