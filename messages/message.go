package messages

type Message struct {
	Endpoint string
	Type     string
	Data     []byte
	err      error
}

func (m Message) Error() error {
	return m.err
}

func ErrorMessage(name string, err error) Message {
	return Message{
		Endpoint: name,
		err:      err,
	}
}
