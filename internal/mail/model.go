package mail

type MailType int

// List of Mail Types we are going to send.
const (
	MailConfirmation MailType = iota + 1
	PassReset
)

// MailData represents the data to be sent to the template of the mail.
type MailData struct {
	Username string
	Code     string
}

// Mail represents a email request
type Mail struct {
	from    string
	to      []string
	subject string
	body    string
	mtype   MailType
	data    *MailData
}
