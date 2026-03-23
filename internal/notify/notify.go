package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
)

// Notification канал уведомлений
type Notification struct {
	ID        string `json:"id"`
	Channel   string `json:"channel"` // telegram, tag, email
	Recipient string `json:"recipient"`
	Enabled   bool   `json:"enabled"`
}

// AlertNotification структура уведомления об алерте
type AlertNotification struct {
	AlertID   int    `json:"alert_id"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

// NotifyService сервис уведомлений
type NotifyService struct {
	notifications []Notification
	mu            sync.RWMutex
	telegramToken string
	tagWebhookURL string
	smtpConfig    SMTPConfig
}

// SMTPConfig конфигурация email
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// NewNotifyService создает сервис уведомлений
func NewNotifyService(telegramToken, tagWebhookURL string) *NotifyService {
	ns := &NotifyService{
		notifications: make([]Notification, 0),
		telegramToken: telegramToken,
		tagWebhookURL: tagWebhookURL,
	}

	// Добавляем уведомления по умолчанию
	ns.AddNotification(Notification{
		ID:        "notify_001",
		Channel:   "telegram",
		Recipient: "-123456789", // ID чата Telegram
		Enabled:   true,
	})

	ns.AddNotification(Notification{
		ID:        "notify_002",
		Channel:   "tag",
		Recipient: "security-team",
		Enabled:   true,
	})

	return ns
}

// AddNotification добавляет канал уведомлений
func (ns *NotifyService) AddNotification(n Notification) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.notifications = append(ns.notifications, n)
}

// GetNotifications возвращает список уведомлений
func (ns *NotifyService) GetNotifications() []Notification {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	notifs := make([]Notification, len(ns.notifications))
	copy(notifs, ns.notifications)
	return notifs
}

// UpdateNotification обновляет уведомление
func (ns *NotifyService) UpdateNotification(id string, enabled bool) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	for i, n := range ns.notifications {
		if n.ID == id {
			ns.notifications[i].Enabled = enabled
			break
		}
	}
}

// SendAlert отправляет уведомление об алерте
func (ns *NotifyService) SendAlert(alert AlertNotification) {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	for _, n := range ns.notifications {
		if !n.Enabled {
			continue
		}

		switch n.Channel {
		case "telegram":
			ns.sendToTelegram(alert, n.Recipient)
		case "tag":
			ns.sendToTag(alert, n.Recipient)
		case "email":
			ns.sendToEmail(alert, n.Recipient)
		}
	}
}

// sendToTelegram отправляет в Telegram
func (ns *NotifyService) sendToTelegram(alert AlertNotification, chatID string) {
	if ns.telegramToken == "" {
		return
	}

	message := fmt.Sprintf(
		"🚨 *АЛЕРТ АНТИФРОД* 🚨\n\n"+
			"*Тип:* %s\n"+
			"*Уровень:* %s\n"+
			"*Сообщение:* %s\n"+
			"*Время:* %s\n\n"+
			"⚠️ Требуется внимание!",
		alert.Type,
		alert.Severity,
		alert.Message,
		alert.Timestamp,
	)

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", ns.telegramToken)

	data := map[string]interface{}{
		"chat_id":    chatID,
		"text":       message,
		"parse_mode": "Markdown",
	}

	jsonData, _ := json.Marshal(data)
	http.Post(url, "application/json", bytes.NewBuffer(jsonData))
}

// sendToTag отправляет в корпоративный мессенджер Tag
func (ns *NotifyService) sendToTag(alert AlertNotification, recipient string) {
	if ns.tagWebhookURL == "" {
		return
	}

	data := map[string]interface{}{
		"recipient": recipient,
		"title":     fmt.Sprintf("🚨 Алерт: %s", alert.Type),
		"message":   alert.Message,
		"severity":  alert.Severity,
		"timestamp": alert.Timestamp,
	}

	jsonData, _ := json.Marshal(data)
	http.Post(ns.tagWebhookURL, "application/json", bytes.NewBuffer(jsonData))
}

// sendToEmail отправляет на email
func (ns *NotifyService) sendToEmail(alert AlertNotification, email string) {
	// Здесь будет логика отправки email
	log.Printf("Sending email to %s: %s", email, alert.Message)
}

// PlayAlertSound воспроизводит звук алерта
func PlayAlertSound() {
	// JavaScript будет воспроизводить звук на клиенте
	// Отправляем событие через WebSocket или HTMX
}
