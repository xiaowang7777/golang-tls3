package message

import golang_tls3 "github.com/xiaowang7777/golang-tls3"

type HelloRetry struct {
	legacyVersion           golang_tls3.ProtocolVersion // tls3必须为 0x0303 tls2的版本号
	random                  golang_tls3.Random          //CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
	legacySessionId         []byte
	cipherSuite             golang_tls3.CipherSuite
	legacyCompressionMethod uint8 // =0
	extensions              []Extension
}
