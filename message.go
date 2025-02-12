package golang_tls3

import "io"

type MessageData interface {
	io.Writer
}

type Message struct {
	MessageType byte
	Length      uint16
	MessageData MessageData
}
