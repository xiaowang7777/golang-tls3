package extensions

import (
	golang_tls3 "github.com/xiaowang7777/golang-tls3"
	"io"
)

//The "signature_algorithms_cert" extension applies to signatures in certificates, and the "signature_algorithms" extension, which originally appeared in TLS 1.2, applies to signatures in CertificateVerify messages.

type SignatureAlgorithmsCert struct {
}

func (s SignatureAlgorithmsCert) Type() golang_tls3.ExtensionType {
	return golang_tls3.SignatureAlgorithmsCert
}

func (s SignatureAlgorithmsCert) Marshal() []byte {
	//TODO implement me
	panic("implement me")
}

func (s SignatureAlgorithmsCert) Unmarshal(bytes []byte) error {
	//TODO implement me
	panic("implement me")
}

func (s SignatureAlgorithmsCert) WriteTo(w io.Writer) (n int64, err error) {
	//TODO implement me
	panic("implement me")
}
