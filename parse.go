package main

import (
	"log"
	"mime"
	"net/mail"
	"strings"
)

func (mp *MessageProcessor) ParseEmailAddress(addr string) EmailAddress {
	parsed, err := mail.ParseAddress(addr)
	if err != nil {
		log.Printf("Error parsing email address: %v", err)
		return EmailAddress{
			Address: strings.Trim(addr, "<>"),
		}
	}

	dec := new(mime.WordDecoder)
	name := parsed.Name
	if name != "" {
		decoded, err := dec.DecodeHeader(name)
		if err == nil {
			name = decoded
		}
		log.Printf("Decoded email address: %v", name)
	}

	return EmailAddress{
		Address: parsed.Address,
		Name:    name,
	}
}

func (mp *MessageProcessor) ParseSubject(subject string) string {
	dec := new(mime.WordDecoder)
	decoded, err := dec.DecodeHeader(subject)
	if err != nil {
		return subject
	}
	return decoded
}

func (mp *MessageProcessor) ParseEmailAddresses(addrs []string) []EmailAddress {
	result := make([]EmailAddress, len(addrs))
	dec := new(mime.WordDecoder)
	for i, addr := range addrs {
		parsed, err := mail.ParseAddress(addr)
		if err != nil {
			result[i] = EmailAddress{
				Address: strings.Trim(addr, "<>"),
			}
			continue
		}

		name := parsed.Name
		if name != "" {
			decoded, err := dec.DecodeHeader(name)
			if err == nil {
				name = decoded
			}
			log.Printf("Decoded email address: %v", name)
		}

		result[i] = EmailAddress{
			Address: parsed.Address,
			Name:    name,
		}
	}
	return result
}

func (mp *MessageProcessor) ParseBody(msg *mail.Message) Body {
	body := Body{}

	return body
}
