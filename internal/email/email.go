package email

import (
	"crypto/tls"
	"fmt"
	"net/smtp"

	email2 "github.com/jordan-wright/email"
)

type Config struct {
	Server string
	Port   string
	Login  string
	Pass   string
}

type MailSender interface {
	SendResetCode(to string, code string) error
	SendConfirmationCode(to string, code string) error
}

type MailSenderClient struct {
	Server string
	Port   string
	Login  string
	Pass   string
}

func NewMailSender(c *Config) *MailSenderClient {
	return &MailSenderClient{
		Server: c.Server,
		Login:  c.Login,
		Pass:   c.Pass,
		Port:   c.Port,
	}
}

func (ms *MailSenderClient) SendResetCode(to string, code string) error {
	auth := smtp.PlainAuth("", ms.Login, ms.Pass, ms.Server)

	e := email2.NewEmail()

	e.From = fmt.Sprintf("BlogIn <%s>", ms.Login)
	e.To = []string{to}
	e.Subject = "Восстановление пароля"
	e.Text = []byte(fmt.Sprintf("Здравствуйте, вы запросили восстановление пароля для приложения BlogIn.\n"+
		"Для продолжения введите указанный код в приложении вместе с новым паролем.\nВаш код: %s\n", code))

	return e.SendWithStartTLS(ms.Server+":"+ms.Port, auth, &tls.Config{InsecureSkipVerify: true})
}

func (ms *MailSenderClient) SendConfirmationCode(to string, code string) error {
	auth := smtp.PlainAuth("", ms.Login, ms.Pass, ms.Server)

	e := email2.NewEmail()

	e.From = fmt.Sprintf("BlogIn <%s>", ms.Login)
	e.To = []string{to}
	e.Subject = "Подтверждение аккаунта"
	e.Text = []byte(fmt.Sprintf("Здравствуйте, вы зарегистрировались в приложении BlogIn.\n"+
		"Для подтверждения аккаунта введите указанный код в приложении.\nВаш код: %s\n", code))

	return e.SendWithStartTLS(ms.Server+":"+ms.Port, auth, &tls.Config{InsecureSkipVerify: true})
}
