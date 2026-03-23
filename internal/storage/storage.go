package storage

import (
	"sync"
	"time"
)

// Session представляет сессию пользователя
type Session struct {
	ID        int       `json:"id"`
	UserID    string    `json:"user_id"`
	IP        string    `json:"ip"`
	RiskScore int       `json:"risk_score"`
	Status    string    `json:"status"` // normal, suspicious, blocked
	CreatedAt time.Time `json:"created_at"`
}

// Transaction представляет транзакцию
type Transaction struct {
	ID        int       `json:"id"`
	UserID    string    `json:"user_id"`
	Amount    float64   `json:"amount"`
	RiskScore int       `json:"risk_score"`
	IsFraud   bool      `json:"is_fraud"`
	CreatedAt time.Time `json:"created_at"`
}

// Alert представляет оповещение
type Alert struct {
	ID         int       `json:"id"`
	Type       string    `json:"type"`
	Severity   string    `json:"severity"` // low, medium, high, critical
	Message    string    `json:"message"`
	Resolved   bool      `json:"resolved"`
	ResolvedBy string    `json:"resolved_by"` // кто решил алерт (ФИО)
	ResolvedAt time.Time `json:"resolved_at"` // когда решили
	CreatedAt  time.Time `json:"created_at"`
}

// Log представляет запись лога
type Log struct {
	ID        int       `json:"id"`
	EventType string    `json:"event_type"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

// Storage хранит все данные в памяти с историей
type Storage struct {
	mu           sync.RWMutex
	Sessions     []Session
	Transactions []Transaction
	Alerts       []Alert
	Logs         []Log
	nextID       map[string]int
	maxHistory   int // количество дней истории
}

// NewStorage создает новое хранилище с историей по умолчанию 1 день
func NewStorage() *Storage {
	return NewStorageWithHistory(1)
}

// NewStorageWithHistory создает новое хранилище с указанным количеством дней истории
func NewStorageWithHistory(days int) *Storage {
	s := &Storage{
		Sessions:     make([]Session, 0),
		Transactions: make([]Transaction, 0),
		Alerts:       make([]Alert, 0),
		Logs:         make([]Log, 0),
		nextID:       make(map[string]int),
		maxHistory:   days,
	}

	// Инициализируем счетчики ID
	s.nextID["session"] = 1
	s.nextID["transaction"] = 1
	s.nextID["alert"] = 1
	s.nextID["log"] = 1

	return s
}

// cleanOldData удаляет старые данные (старше maxHistory дней)
func (s *Storage) cleanOldData() {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().AddDate(0, 0, -s.maxHistory)

	// Очищаем сессии
	newSessions := make([]Session, 0)
	for _, sess := range s.Sessions {
		if sess.CreatedAt.After(cutoff) {
			newSessions = append(newSessions, sess)
		}
	}
	s.Sessions = newSessions

	// Очищаем транзакции
	newTransactions := make([]Transaction, 0)
	for _, tx := range s.Transactions {
		if tx.CreatedAt.After(cutoff) {
			newTransactions = append(newTransactions, tx)
		}
	}
	s.Transactions = newTransactions

	// Очищаем алерты (оставляем все, но для истории)
	newAlerts := make([]Alert, 0)
	for _, alert := range s.Alerts {
		if alert.CreatedAt.After(cutoff) || !alert.Resolved {
			newAlerts = append(newAlerts, alert)
		}
	}
	s.Alerts = newAlerts

	// Логи очищаем агрессивнее
	newLogs := make([]Log, 0)
	for _, log := range s.Logs {
		if log.CreatedAt.After(cutoff) {
			newLogs = append(newLogs, log)
		}
	}
	s.Logs = newLogs
}

// AddSession добавляет сессию
func (s *Storage) AddSession(userID, ip string, riskScore int, status string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextID["session"]
	s.nextID["session"]++

	session := Session{
		ID:        id,
		UserID:    userID,
		IP:        ip,
		RiskScore: riskScore,
		Status:    status,
		CreatedAt: time.Now(),
	}

	s.Sessions = append([]Session{session}, s.Sessions...)

	// Периодически чистим старые данные
	if len(s.Sessions)%100 == 0 {
		go s.cleanOldData()
	}

	return id
}

// AddTransaction добавляет транзакцию
func (s *Storage) AddTransaction(userID string, amount float64, riskScore int, isFraud bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextID["transaction"]
	s.nextID["transaction"]++

	transaction := Transaction{
		ID:        id,
		UserID:    userID,
		Amount:    amount,
		RiskScore: riskScore,
		IsFraud:   isFraud,
		CreatedAt: time.Now(),
	}

	s.Transactions = append([]Transaction{transaction}, s.Transactions...)

	// Периодически чистим старые данные
	if len(s.Transactions)%100 == 0 {
		go s.cleanOldData()
	}

	return id
}

// AddAlert добавляет алерт
func (s *Storage) AddAlert(alertType, severity, message string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextID["alert"]
	s.nextID["alert"]++

	alert := Alert{
		ID:         id,
		Type:       alertType,
		Severity:   severity,
		Message:    message,
		Resolved:   false,
		ResolvedBy: "",
		ResolvedAt: time.Time{},
		CreatedAt:  time.Now(),
	}

	s.Alerts = append([]Alert{alert}, s.Alerts...)
	return id
}

// ResolveAlertAuto автоматически разрешает алерт
func (s *Storage) ResolveAlertAuto(id int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, alert := range s.Alerts {
		if alert.ID == id && !alert.Resolved {
			s.Alerts[i].Resolved = true
			s.Alerts[i].ResolvedBy = ""
			s.Alerts[i].ResolvedAt = time.Now()
			return true
		}
	}
	return false
}

// ResolveAlertManual разрешает алерт вручную с указанием сотрудника
func (s *Storage) ResolveAlertManual(id int, userName string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, alert := range s.Alerts {
		if alert.ID == id && !alert.Resolved {
			s.Alerts[i].Resolved = true
			s.Alerts[i].ResolvedBy = userName
			s.Alerts[i].ResolvedAt = time.Now()
			return true
		}
	}
	return false
}

// AddLog добавляет лог
func (s *Storage) AddLog(eventType, details string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextID["log"]
	s.nextID["log"]++

	log := Log{
		ID:        id,
		EventType: eventType,
		Details:   details,
		CreatedAt: time.Now(),
	}

	s.Logs = append([]Log{log}, s.Logs...)
	return id
}

// GetActiveSessions возвращает количество активных сессий (за последний час)
func (s *Storage) GetActiveSessions() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	oneHourAgo := time.Now().Add(-1 * time.Hour)
	for _, session := range s.Sessions {
		if session.Status != "blocked" && session.CreatedAt.After(oneHourAgo) {
			count++
		}
	}
	return count
}

// GetTotalTransactions возвращает общее количество транзакций
func (s *Storage) GetTotalTransactions() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.Transactions)
}

// GetActiveAlerts возвращает количество активных алертов
func (s *Storage) GetActiveAlerts() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, alert := range s.Alerts {
		if !alert.Resolved {
			count++
		}
	}
	return count
}

// GetFraudRate возвращает процент мошенничества
func (s *Storage) GetFraudRate() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.Transactions) == 0 {
		return 0
	}

	fraudCount := 0
	for _, t := range s.Transactions {
		if t.IsFraud {
			fraudCount++
		}
	}
	return float64(fraudCount) / float64(len(s.Transactions)) * 100
}

// GetSessions возвращает список сессий
func (s *Storage) GetSessions(limit int) []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit > len(s.Sessions) {
		limit = len(s.Sessions)
	}
	return s.Sessions[:limit]
}

// GetTransactions возвращает список транзакций
func (s *Storage) GetTransactions(limit int) []Transaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit > len(s.Transactions) {
		limit = len(s.Transactions)
	}
	return s.Transactions[:limit]
}

// GetAlerts возвращает список алертов
func (s *Storage) GetAlerts(limit int) []Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit > len(s.Alerts) {
		limit = len(s.Alerts)
	}
	return s.Alerts[:limit]
}

// GetAlertsFiltered возвращает отфильтрованные алерты
func (s *Storage) GetAlertsFiltered(severity, resolved string) []Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Alert, 0)
	for _, alert := range s.Alerts {
		if severity != "" && alert.Severity != severity {
			continue
		}
		if resolved != "" {
			isResolved := resolved == "true"
			if alert.Resolved != isResolved {
				continue
			}
		}
		result = append(result, alert)
	}
	return result
}

// GetLogs возвращает список логов
func (s *Storage) GetLogs(limit int) []Log {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit > len(s.Logs) {
		limit = len(s.Logs)
	}
	return s.Logs[:limit]
}

// GetTransactionsFiltered возвращает транзакции с фильтрацией
func (s *Storage) GetTransactionsFiltered(userID, status, dateFrom, dateTo string, minAmount, maxAmount float64) []Transaction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Transaction, 0)

	for _, t := range s.Transactions {
		// Фильтр по пользователю
		if userID != "" && t.UserID != userID {
			continue
		}

		// Фильтр по статусу (мошенничество)
		if status != "" {
			if status == "fraud" && !t.IsFraud {
				continue
			}
			if status == "normal" && t.IsFraud {
				continue
			}
		}

		// Фильтр по дате
		if dateFrom != "" {
			from, err := time.Parse("2006-01-02", dateFrom)
			if err == nil && t.CreatedAt.Before(from) {
				continue
			}
		}
		if dateTo != "" {
			to, err := time.Parse("2006-01-02", dateTo)
			if err == nil && t.CreatedAt.After(to.Add(24*time.Hour)) {
				continue
			}
		}

		// Фильтр по сумме
		if minAmount > 0 && t.Amount < minAmount {
			continue
		}
		if maxAmount > 0 && t.Amount > maxAmount {
			continue
		}

		result = append(result, t)
	}

	return result
}

// GetSessionsFiltered возвращает сессии с фильтрацией
func (s *Storage) GetSessionsFiltered(userID, ip, status string) []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Session, 0)

	for _, sess := range s.Sessions {
		if userID != "" && sess.UserID != userID {
			continue
		}
		if ip != "" && sess.IP != ip {
			continue
		}
		if status != "" && sess.Status != status {
			continue
		}
		result = append(result, sess)
	}

	return result
}

// AddTransactionWithDate добавляет транзакцию с указанной датой (для исторических данных)
func (s *Storage) AddTransactionWithDate(userID string, amount float64, riskScore int, isFraud bool, date time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextID["transaction"]
	s.nextID["transaction"]++

	transaction := Transaction{
		ID:        id,
		UserID:    userID,
		Amount:    amount,
		RiskScore: riskScore,
		IsFraud:   isFraud,
		CreatedAt: date,
	}

	s.Transactions = append([]Transaction{transaction}, s.Transactions...)
	return id
}

// AddSessionWithDate добавляет сессию с указанной датой (для исторических данных)
func (s *Storage) AddSessionWithDate(userID, ip string, riskScore int, status string, date time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextID["session"]
	s.nextID["session"]++

	session := Session{
		ID:        id,
		UserID:    userID,
		IP:        ip,
		RiskScore: riskScore,
		Status:    status,
		CreatedAt: date,
	}

	s.Sessions = append([]Session{session}, s.Sessions...)
	return id
}

// AddAlertWithDate добавляет алерт с указанной датой (для исторических данных)
func (s *Storage) AddAlertWithDate(alertType, severity, message string, date time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextID["alert"]
	s.nextID["alert"]++

	alert := Alert{
		ID:         id,
		Type:       alertType,
		Severity:   severity,
		Message:    message,
		Resolved:   false,
		ResolvedBy: "",
		ResolvedAt: time.Time{},
		CreatedAt:  date,
	}

	s.Alerts = append([]Alert{alert}, s.Alerts...)
	return id
}

// GetStatsByDateRange возвращает статистику за период
func (s *Storage) GetStatsByDateRange(startDate, endDate time.Time) map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]interface{}{
		"sessions":     0,
		"transactions": 0,
		"fraud_count":  0,
		"total_amount": 0.0,
	}

	for _, sess := range s.Sessions {
		if sess.CreatedAt.After(startDate) && sess.CreatedAt.Before(endDate) {
			stats["sessions"] = stats["sessions"].(int) + 1
		}
	}

	for _, tx := range s.Transactions {
		if tx.CreatedAt.After(startDate) && tx.CreatedAt.Before(endDate) {
			stats["transactions"] = stats["transactions"].(int) + 1
			stats["total_amount"] = stats["total_amount"].(float64) + tx.Amount
			if tx.IsFraud {
				stats["fraud_count"] = stats["fraud_count"].(int) + 1
			}
		}
	}

	return stats
}

func (s *Storage) ResolveAllAlerts() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	resolvedCount := 0
	for i := range s.Alerts {
		if !s.Alerts[i].Resolved {
			s.Alerts[i].Resolved = true
			s.Alerts[i].ResolvedBy = "System (Bulk Action)"
			s.Alerts[i].ResolvedAt = time.Now()
			resolvedCount++
		}
	}
	return resolvedCount
}
