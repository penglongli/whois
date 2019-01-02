package whois

import (
	"strings"
	"fmt"
)

// Record represents a parsed whois response.
type Record struct {
	// Query Domain name
	Domain   string
	// Query domain's registrar
	Registrar    string

	// Query domain's create time, expire time
	CreationDate string
	ExpiryDate   string

	// Query domain's contact email, phone
	ContactEmail string
	ContactPhone string

	// Query domain's name_servers
	NameServers  []string
}

var (
	parseMap map[string]func(res *Response)(record *Record)
)

func init() {
	parseMap = map[string]func(res *Response)(record *Record) {
		"com": parseGeneral,
		"net": parseGeneral,
		"top": parseGeneral,
		"tech": parseGeneral,
		"org": parseGeneral,
		"gov": parseGeneral,
		"edu": parseEdu,
		"pub": parseGeneral,
		"cn": parseGeneral,
		"tw": parseTW,
		"app": parseGeneral,
		"me": parseGeneral,
		"cc": parseGeneral,
		"xyz": parseGeneral,
		"wang": parseGeneral,
		"site":parseGeneral,
		"club":parseGeneral,
		"online":parseGeneral,
		"red":parseGeneral,
		"link": parseGeneral,
		"info": parseGeneral,
	}
}

// Parse whois msg
func (res *Response) Parse() (record *Record, err error) {
	q := res.Query; s := strings.Split(q, ".")
	if len(s) != 2 {
		return nil, fmt.Errorf("error domain format: %s", q)
	}

	suffix := s[1]; msg := res.String()
	if msg == "" {
		return nil, fmt.Errorf("empty response for %s", q)
	}

	f := parseMap[suffix]
	if f == nil {
		return nil, fmt.Errorf("not support: %s", suffix)
	}
	return f(res), nil
}

func parseGeneral(res *Response) (record *Record) {
	record = &Record{Domain: res.Query}; msg := res.String()

	msgSlice := strings.Split(msg, "\r\n")
	m := make(map[string]string)
	for _, item := range msgSlice {
		s := strings.Split(item, ": ")
		if len(s) != 2 {
			continue
		}
		if strings.TrimSpace(s[0]) == "Name Server" {
			nameServer := s[1]
			record.NameServers = append(record.NameServers, nameServer)
			continue
		}

		m[strings.TrimSpace(s[0])] = s[1]
	}
	record.Registrar = m["Registrar"]
	record.CreationDate = strings.Split(m["Creation Date"], "T")[0]
	record.ExpiryDate = strings.Split(m["Registry Expiry Date"], "T")[0]
	record.ContactEmail = strings.TrimSpace(m["Registrar Abuse Contact Email"])
	record.ContactPhone = strings.TrimSpace(m["Registrar Abuse Contact Phone"])
	return record
}

func parseEdu(res *Response) (record *Record) {
	return nil
}

func parseTW(res *Response) (record *Record) {
	record = &Record{Domain: res.Query}; msg := res.String()

	msgSlice := strings.Split(msg, "\n\n")
	for _, item := range msgSlice {
		if strings.Contains(item, "expire") {
			t := strings.Split(item, "\n")
			if len(t) != 2 {
				continue
			}

			record.ExpiryDate = strings.Split(strings.TrimSpace(t[0]), " ")[3]
			record.CreationDate = strings.Split(strings.TrimSpace(t[1]), " ")[3]
			continue
		}
		if strings.Contains(item, "Domain servers") {
			t := strings.Split(item, "\n")
			for i := 1; i < len(t); i++ {
				record.NameServers = append(record.NameServers, strings.TrimSpace(t[i]))
			}
			continue
		}
	}
	return record
}
