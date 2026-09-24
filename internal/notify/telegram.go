package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TelegramSender returns a Sender that delivers notifications to a Telegram chat.
//
// The channel config (notification_channels.config JSONB) must contain:
//
//	bot_token string — Telegram Bot API token (e.g. "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11")
//	chat_id   string — Target chat or channel ID (e.g. "-100123456789" or "@channelname")
//
// Uses the standard Telegram sendMessage endpoint:
//
//	POST https://api.telegram.org/bot<token>/sendMessage
func TelegramSender(client *http.Client) Sender {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return func(ctx context.Context, d Delivery) error {
		cfg := d.ChannelConfig
		botToken, _ := cfg["bot_token"].(string)
		if botToken == "" {
			return fmt.Errorf("telegram sender: bot_token not configured for channel %s", d.ChannelID)
		}
		chatID, _ := cfg["chat_id"].(string)
		if chatID == "" {
			return fmt.Errorf("telegram sender: chat_id not configured for channel %s", d.ChannelID)
		}

		text := formatTelegramMessage(d)

		payload := map[string]string{
			"chat_id":    chatID,
			"text":       text,
			"parse_mode": "Markdown",
		}
		bodyBytes, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("telegram sender: marshal request: %w", err)
		}

		endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("telegram sender: create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("telegram sender: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			var tgErr struct {
				Description string `json:"description"`
				ErrorCode   int    `json:"error_code"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&tgErr)
			return fmt.Errorf("telegram sender: API returned status %d: %s", resp.StatusCode, tgErr.Description)
		}
		return nil
	}
}

func formatTelegramMessage(d Delivery) string {
	icon := "ℹ️"
	switch d.Severity {
	case SeverityCritical:
		icon = "🚨"
	case SeverityWarning:
		icon = "⚠️"
	}

	title := d.Title
	if title == "" {
		title = d.Event
	}

	body := d.Body
	if body == "" {
		return fmt.Sprintf("%s *%s*", icon, title)
	}
	return fmt.Sprintf("%s *%s*\n\n%s", icon, title, body)
}
