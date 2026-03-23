package rules

import (
	"fmt"
	"sync"
	"time"
)

// RiskLevel уровень риска
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// Rule правило детекции
type Rule struct {
	ID          string                                 `json:"id"`
	Name        string                                 `json:"name"`
	NameRu      string                                 `json:"name_ru"`
	Description string                                 `json:"description"`
	Weight      int                                    `json:"weight"` // вес правила (1-100)
	Enabled     bool                                   `json:"enabled"`
	Condition   func(data map[string]interface{}) bool `json:"-"`
	Action      string                                 `json:"action"` // block, alert, log
}

// TransactionData данные транзакции для проверки правил
type TransactionData struct {
	UserID    string
	Amount    float64
	IP        string
	Timestamp time.Time
	DeviceID  string
	UserAgent string
	Velocity  int // количество транзакций за последний час
	AvgAmount float64
	IsFraud   bool
}

// RuleEngine движок правил
type RuleEngine struct {
	rules     []Rule
	rulesLock sync.RWMutex
	history   map[string][]TransactionData
	histLock  sync.RWMutex
}

// NewRuleEngine создает новый движок правил
func NewRuleEngine() *RuleEngine {
	re := &RuleEngine{
		rules:   make([]Rule, 0),
		history: make(map[string][]TransactionData),
	}

	re.initRules()
	return re
}

// initRules инициализирует правила по умолчанию
func (re *RuleEngine) initRules() {
	re.rules = []Rule{
		{
			ID:          "rule_001",
			Name:        "High Amount",
			NameRu:      "Крупная сумма",
			Description: "Транзакция превышает 50 000 рублей",
			Weight:      30,
			Enabled:     true,
			Action:      "alert",
			Condition: func(data map[string]interface{}) bool {
				amount, ok := data["amount"].(float64)
				return ok && amount > 50000
			},
		},
		{
			ID:          "rule_002",
			Name:        "Velocity Check",
			NameRu:      "Высокая скорость",
			Description: "Более 5 транзакций за последний час",
			Weight:      40,
			Enabled:     true,
			Action:      "alert",
			Condition: func(data map[string]interface{}) bool {
				velocity, ok := data["velocity"].(int)
				return ok && velocity > 5
			},
		},
		{
			ID:          "rule_003",
			Name:        "Suspicious IP",
			NameRu:      "Подозрительный IP",
			Description: "IP адрес из неразрешенной страны",
			Weight:      50,
			Enabled:     true,
			Action:      "block",
			Condition: func(data map[string]interface{}) bool {
				blocked, ok := data["ip_blocked"].(bool)
				return ok && blocked
			},
		},
		{
			ID:          "rule_004",
			Name:        "Unusual Amount",
			NameRu:      "Нетипичная сумма",
			Description: "Сумма более чем в 3 раза превышает среднюю",
			Weight:      35,
			Enabled:     true,
			Action:      "alert",
			Condition: func(data map[string]interface{}) bool {
				amount, ok1 := data["amount"].(float64)
				avgAmount, ok2 := data["avg_amount"].(float64)
				return ok1 && ok2 && amount > avgAmount*3 && avgAmount > 0
			},
		},
		{
			ID:          "rule_005",
			Name:        "Night Transaction",
			NameRu:      "Ночная транзакция",
			Description: "Транзакция в ночное время (00:00 - 06:00)",
			Weight:      20,
			Enabled:     true,
			Action:      "alert",
			Condition: func(data map[string]interface{}) bool {
				timestamp, ok := data["timestamp"].(time.Time)
				if !ok {
					return false
				}
				hour := timestamp.Hour()
				return hour >= 0 && hour < 6
			},
		},
		{
			ID:          "rule_006",
			Name:        "Rapid Succession",
			NameRu:      "Быстрая последовательность",
			Description: "Более 3 транзакций за 5 минут",
			Weight:      45,
			Enabled:     true,
			Action:      "block",
			Condition: func(data map[string]interface{}) bool {
				velocity, ok := data["velocity_5min"].(int)
				return ok && velocity > 3
			},
		},
	}
}

// AddRule добавляет новое правило
func (re *RuleEngine) AddRule(rule Rule) {
	re.rulesLock.Lock()
	defer re.rulesLock.Unlock()
	re.rules = append(re.rules, rule)
}

// UpdateRule обновляет правило
func (re *RuleEngine) UpdateRule(id string, enabled bool, weight int) {
	re.rulesLock.Lock()
	defer re.rulesLock.Unlock()

	for i, rule := range re.rules {
		if rule.ID == id {
			re.rules[i].Enabled = enabled
			re.rules[i].Weight = weight
			break
		}
	}
}

// GetRules возвращает список правил
func (re *RuleEngine) GetRules() []Rule {
	re.rulesLock.RLock()
	defer re.rulesLock.RUnlock()

	rules := make([]Rule, len(re.rules))
	copy(rules, re.rules)
	return rules
}

// Evaluate оценивает транзакцию по всем правилам
func (re *RuleEngine) Evaluate(tx TransactionData) (int, RiskLevel, string, bool) {
	re.rulesLock.RLock()
	defer re.rulesLock.RUnlock()

	// Сохраняем в историю
	re.addToHistory(tx.UserID, tx)

	// Получаем дополнительные данные
	velocity := re.getVelocity(tx.UserID, time.Hour)
	velocity5min := re.getVelocity(tx.UserID, 5*time.Minute)
	avgAmount := re.getAvgAmount(tx.UserID)

	totalScore := 0
	triggeredRules := make([]string, 0)
	shouldBlock := false

	for _, rule := range re.rules {
		if !rule.Enabled {
			continue
		}

		data := map[string]interface{}{
			"amount":        tx.Amount,
			"velocity":      velocity,
			"velocity_5min": velocity5min,
			"avg_amount":    avgAmount,
			"timestamp":     tx.Timestamp,
			"ip_blocked":    false, // будет установлено извне
		}

		if rule.Condition(data) {
			totalScore += rule.Weight
			triggeredRules = append(triggeredRules, rule.NameRu)
			if rule.Action == "block" {
				shouldBlock = true
			}
		}
	}

	// Определяем уровень риска
	riskLevel := RiskLow
	switch {
	case totalScore >= 80:
		riskLevel = RiskCritical
	case totalScore >= 50:
		riskLevel = RiskHigh
	case totalScore >= 25:
		riskLevel = RiskMedium
	}

	// Формируем сообщение
	message := ""
	if len(triggeredRules) > 0 {
		message = fmt.Sprintf("Сработали правила: %v", triggeredRules)
	}

	return totalScore, riskLevel, message, shouldBlock
}

// addToHistory добавляет транзакцию в историю
func (re *RuleEngine) addToHistory(userID string, tx TransactionData) {
	re.histLock.Lock()
	defer re.histLock.Unlock()

	history := re.history[userID]
	history = append(history, tx)

	// Оставляем только последние 100 транзакций
	if len(history) > 100 {
		history = history[len(history)-100:]
	}
	re.history[userID] = history
}

// getVelocity возвращает количество транзакций за период
func (re *RuleEngine) getVelocity(userID string, period time.Duration) int {
	re.histLock.RLock()
	defer re.histLock.RUnlock()

	history, ok := re.history[userID]
	if !ok {
		return 0
	}

	cutoff := time.Now().Add(-period)
	count := 0
	for _, tx := range history {
		if tx.Timestamp.After(cutoff) {
			count++
		}
	}
	return count
}

// getAvgAmount возвращает среднюю сумму транзакций
func (re *RuleEngine) getAvgAmount(userID string) float64 {
	re.histLock.RLock()
	defer re.histLock.RUnlock()

	history, ok := re.history[userID]
	if !ok || len(history) == 0 {
		return 0
	}

	var total float64
	for _, tx := range history {
		total += tx.Amount
	}
	return total / float64(len(history))
}
