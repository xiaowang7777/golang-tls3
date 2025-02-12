package message

import (
	golang_tls3 "github.com/xiaowang7777/golang-tls3"
	"io"
)

type Extension interface {
	Type() golang_tls3.ExtensionType
	Marshal() []byte
	Unmarshal([]byte) error
	io.WriterTo
}
