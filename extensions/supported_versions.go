package extensions

import (
	"errors"
	golang_tls3 "github.com/xiaowang7777/golang-tls3"
	"io"
)

// A server which negotiates a version of TLS prior to TLS 1.3 MUST set
//ServerHello.version and MUST NOT send the "supported_versions"
//extension.

type SupportedVersions struct {
	messageType golang_tls3.MessageType

	selectedVersion golang_tls3.ProtocolVersion   // ServerHello
	versions        []golang_tls3.ProtocolVersion // ClientHello
}

func NewSupportedVersionsExtension(messageType golang_tls3.MessageType) (*SupportedVersions, error) {
	if messageType != golang_tls3.ClientHello && messageType != golang_tls3.ServerHello {
		return nil, errors.New("")
	}

	return &SupportedVersions{
		messageType: messageType,
	}, nil
}

func (s SupportedVersions) Type() golang_tls3.ExtensionType {
	return golang_tls3.SupportedVersions
}

func (s SupportedVersions) Marshal() []byte {
	switch s.messageType {
	case golang_tls3.ClientHello:
		var res []byte
		for _, v := range s.versions {
			res = append(res, v.Marshal()...)
		}
		return res
	case golang_tls3.ServerHello:
		return s.selectedVersion.Marshal()
	default:
		return nil
	}
}

func (s SupportedVersions) Unmarshal(data []byte) error {
	if len(data)%2 != 0 {
		return errors.New("")
	}

	switch s.messageType {
	case golang_tls3.ClientHello:
		s.versions = make([]golang_tls3.ProtocolVersion, len(data)/2)
		for i := 0; i < len(data)/2; i += 2 {
			s.versions[i] = golang_tls3.ProtocolVersion(uint16(data[i])<<8 | uint16(data[i+1]))
		}
	case golang_tls3.ServerHello:
		s.selectedVersion = golang_tls3.ProtocolVersion(uint16(data[0])<<8 | uint16(data[1]))
	default:
		return errors.New("")
	}
	return nil
}

func (s SupportedVersions) WriteTo(w io.Writer) (n int64, err error) {
	write, err := w.Write(s.Marshal())
	n = int64(write)
	return
}
