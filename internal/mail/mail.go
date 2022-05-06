package mail

import (
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"net/http"

	"github.com/patriciabonaldy/authentication/internal/config"
	"github.com/patriciabonaldy/authentication/internal/platform/logger"
)

type Service interface {
	CreateMail(mailReq *Mail) []byte
	SendMail(mailReq *Mail) error
	NewMail(from string, to []string, subject string, mailType MailType, data *MailData) *Mail
}

// mailService is the sendgrid implementation of our mailService.
type mailService struct {
	logger logger.Logger
	config *config.Mail
}

// New returns a new instance of mailService
func New(logger logger.Logger, config *config.Mail) Service {
	return &mailService{logger, config}
}

func (s *mailService) CreateMail(mailReq *Mail) []byte {
	m := mail.NewV3Mail()
	m.SetFrom(mail.NewEmail(s.config.Name, mailReq.from))
	m.SetTemplateID(s.config.MailVerifTemplateID)
	if mailReq.mtype == PassReset {
		m.SetTemplateID(s.config.PassResetTemplateID)
	}

	p := mail.NewPersonalization()
	tos := make([]*mail.Email, 0)
	for _, to := range mailReq.to {
		tos = append(tos, mail.NewEmail("user", to))
	}

	p.AddTos(tos...)
	p.SetDynamicTemplateData("Username", mailReq.data.Username)
	p.SetDynamicTemplateData("Code", mailReq.data.Code)

	m.AddPersonalizations(p)
	return mail.GetRequestBody(m)
}

func (s *mailService) SendMail(mailReq *Mail) error {
	request := sendgrid.GetRequest(s.config.SendGridAPIKey, "/v3/mail/send", "https://api.sendgrid.com")
	request.Method = http.MethodPost

	request.Body = s.CreateMail(mailReq)
	response, err := sendgrid.API(request)
	if err != nil {
		s.logger.Error("unable to send mail", "error", err)
		return err
	}

	s.logger.Info("mail sent successfully", "sent status code", response.StatusCode)
	return nil
}

func (s *mailService) NewMail(from string, to []string, subject string, mailType MailType, data *MailData) *Mail {
	return &Mail{
		from:    from,
		to:      to,
		subject: subject,
		mtype:   mailType,
		data:    data,
	}
}
