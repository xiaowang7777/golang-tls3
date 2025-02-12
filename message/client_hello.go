package message

import golang_tls3 "github.com/xiaowang7777/golang-tls3"

type ClientHello struct {
	legacyVersion            golang_tls3.ProtocolVersion // tls3 固定tls1.2 0x0303
	random                   golang_tls3.Random
	legacySessionID          []byte                    // 0-32
	cipherSuites             []golang_tls3.CipherSuite // 2-(2^16)-2
	legacyCompressionMethods []byte                    // 1-(2^8)-1
	extensions               []Extension               // 8-(2^16-1)
}
