package notify

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
)

// SMTPSender returns a Sender that delivers notifications via SMTP.
//
// The channel config (notification_channels.config JSONB) must contain:
//
//	smtp_host    string  — SMTP server host (e.g. "smtp.example.com")
//	smtp_port    string  — SMTP server port (e.g. "587", "465", "25")
//	smtp_user    string  — SMTP auth username (empty = no auth)
//	smtp_pass    string  — SMTP auth password (empty = no auth)
//	from_address string  — sender address (e.g. "alerts@example.com")
//	to_address   string  — recipient address (channel-level default)
//
// If smtp_host is missing or empty, the sender returns an error so the
// delivery is retried after the operator configures the channel.
func SMTPSender() Sender {
	return func(ctx context.Context, d Delivery) error {
		cfg := d.ChannelConfig
		host, _ := cfg["smtp_host"].(string)
		if host == "" {
			return fmt.Errorf("smtp sender: smtp_host not configured for channel %s", d.ChannelID)
		}
		port, _ := cfg["smtp_port"].(string)
		if port == "" {
			port = "587"
		}
		user, _ := cfg["smtp_user"].(string)
		pass, _ := cfg["smtp_pass"].(string)
		from, _ := cfg["from_address"].(string)
		if from == "" {
			from = "notifications@jawaker.local"
		}
		to, _ := cfg["to_address"].(string)
		if to == "" {
			return fmt.Errorf("smtp sender: to_address not configured for channel %s", d.ChannelID)
		}

		subject := d.Title
		if subject == "" {
			subject = d.Event
		}
		body := d.Body
		if body == "" {
			body = d.Title
		}

		msg := buildMIMEMessage(from, to, subject, body)
		addr := host + ":" + port

		var auth smtp.Auth
		if user != "" && pass != "" {
			auth = smtp.PlainAuth("", user, pass, host)
		}

		if err := smtp.SendMail(addr, auth, from, []string{to}, []byte(msg)); err != nil {
			return fmt.Errorf("smtp sender: %w", err)
		}
		return nil
	}
}

func buildMIMEMessage(from, to, subject, body string) string {
	var sb strings.Builder
	sb.WriteString("From: " + from + "\r\n")
	sb.WriteString("To: " + to + "\r\n")
	sb.WriteString("Subject: " + subject + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}
