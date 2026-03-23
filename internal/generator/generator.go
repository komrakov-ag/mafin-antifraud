package generator

import (
	"fmt"
	"log"
	"math/rand"
	"time"

	"antifraud-system/internal/geo"
	"antifraud-system/internal/rules"
	"antifraud-system/internal/storage"
)

type DataGenerator struct {
	store           *storage.Storage
	geoService      *geo.GeoService
	ruleEngine      *rules.RuleEngine
	targetFraudRate float64
}

func NewDataGenerator(s *storage.Storage, g *geo.GeoService, r *rules.RuleEngine) *DataGenerator {
	return &DataGenerator{
		store:      s,
		geoService: g,
		ruleEngine: r,
	}
}

func (g *DataGenerator) StartWithTargetFraudRate(targetRate float64) {
	g.targetFraudRate = targetRate
	g.generateHistoricalData(10) // 10 дней истории
	g.Start()
}

func (g *DataGenerator) generateHistoricalData(days int) {
	log.Printf("Generating %d days of historical data...", days)

	// Целевой уровень фрода снижается со временем (эффективность системы растет)
	for day := days; day >= 0; day-- {
		date := time.Now().AddDate(0, 0, -day)

		// Чем дальше в прошлое, тем выше фрод (было хуже)
		historicalFraudRate := g.targetFraudRate + float64(days-day)*0.5
		if historicalFraudRate > 15 {
			historicalFraudRate = 15
		}

		// Количество транзакций за день
		txCount := rand.Intn(200) + 100

		for i := 0; i < txCount; i++ {
			// Генерируем транзакцию с исторической датой
			g.generateHistoricalTransaction(date, historicalFraudRate)
		}

		log.Printf("Day %d: generated %d transactions, fraud rate target %.1f%%", day, txCount, historicalFraudRate)
	}

	log.Printf("Historical data generation complete. Current fraud rate: %.1f%%", g.store.GetFraudRate())
}

func (g *DataGenerator) generateHistoricalTransaction(date time.Time, targetFraudRate float64) {
	userID := fmt.Sprintf("user_%03d", rand.Intn(200))
	amount := float64(rand.Intn(50000) + 100)

	// Определяем, будет ли транзакция фродовой с учетом целевого уровня
	isFraud := rand.Float64()*100 < targetFraudRate

	riskScore := 0
	if isFraud {
		riskScore = rand.Intn(40) + 60 // 60-100
	} else {
		riskScore = rand.Intn(60) // 0-59
	}

	// Создаем транзакцию с указанной датой
	g.store.AddTransactionWithDate(userID, amount, riskScore, isFraud, date)

	// Создаем сессию для пользователя
	ip := g.generateIP()
	status := "normal"
	if isFraud {
		status = "suspicious"
	}
	g.store.AddSessionWithDate(userID, ip, riskScore, status, date)

	// Создаем алерт если нужно
	if isFraud && riskScore > 80 {
		g.store.AddAlertWithDate("Fraudulent Transaction", "high",
			fmt.Sprintf("Fraud transaction: %.2f RUB from %s", amount, userID), date)
	}
}

func (g *DataGenerator) generateIP() string {
	// 85% российские IP
	if rand.Float32() < 0.85 {
		ruIPs := []string{
			"91.200.42.1", "95.167.120.1", "188.162.64.1", "176.59.0.1", "109.194.0.1",
			"93.80.0.1", "85.140.0.1", "46.0.0.1", "213.87.0.1", "31.173.0.1",
		}
		return ruIPs[rand.Intn(len(ruIPs))]
	}
	// Иностранные IP
	foreignIPs := []string{"45.33.22.11", "185.130.5.253", "94.102.61.78", "8.8.8.8", "1.1.1.1"}
	return foreignIPs[rand.Intn(len(foreignIPs))]
}

func (g *DataGenerator) Start() {
	// Сначала генерируем 50 начальных записей
	g.generateBatch(50)
	log.Println("✅ Initial data generated")

	ticker := time.NewTicker(3 * time.Second)
	go func() {
		for range ticker.C {
			batchSize := rand.Intn(8) + 3
			g.generateBatch(batchSize)
		}
	}()

	log.Println("✅ Data generator started")
}

func (g *DataGenerator) generateBatch(count int) {
	for i := 0; i < count; i++ {
		r := rand.Float32()
		switch {
		case r < 0.3:
			g.createSession()
		case r < 0.8:
			g.createTransaction()
		default:
			g.createLog()
		}
	}
}

func (g *DataGenerator) createSession() {
	userID := fmt.Sprintf("user_%03d", rand.Intn(200))
	ip := g.generateIP()

	riskScore := rand.Intn(101)

	var status string
	switch {
	case riskScore > 90:
		status = "blocked"
	case riskScore > 70:
		status = "suspicious"
	default:
		status = "normal"
	}

	// Проверка гео-блокировки
	if g.geoService.IsIPBlocked(ip) {
		status = "blocked"
		riskScore = 100
		g.store.AddLog("IP_BLOCKED", fmt.Sprintf("Blocked IP %s from %s", ip, userID))
	}

	g.store.AddSession(userID, ip, riskScore, status)

	if riskScore > 80 {
		g.store.AddAlert("High Risk Session", "high",
			fmt.Sprintf("Session for user %s has risk score %d from IP %s", userID, riskScore, ip))
	}
}

func (g *DataGenerator) createTransaction() {
	userID := fmt.Sprintf("user_%03d", rand.Intn(200))
	amount := float64(rand.Intn(50000) + 100)
	ip := g.generateIP()

	// Получаем исторические данные для правил
	transactions := g.store.GetTransactionsFiltered(userID, "", "", "", 0, 0)
	var avgAmount float64
	if len(transactions) > 0 {
		var total float64
		for _, t := range transactions {
			total += t.Amount
		}
		avgAmount = total / float64(len(transactions))
	}

	// Создаем данные для оценки риска
	txData := rules.TransactionData{
		UserID:    userID,
		Amount:    amount,
		IP:        ip,
		Timestamp: time.Now(),
		AvgAmount: avgAmount,
	}

	// Оцениваем риск по правилам
	riskScore, riskLevel, message, shouldBlock := g.ruleEngine.Evaluate(txData)

	// Проверка гео-блокировки
	if g.geoService.IsIPBlocked(ip) {
		riskScore = 100
		shouldBlock = true
		message = "IP из неразрешенной страны"
	}

	// Контроль целевого уровня фрода
	isFraud := false
	if g.targetFraudRate > 0 {
		// Адаптируем вероятность фрода под целевой уровень
		currentRate := g.store.GetFraudRate()
		if currentRate < g.targetFraudRate {
			// Нужно больше фрода
			isFraud = riskScore > 70 || shouldBlock || rand.Float64() < 0.3
		} else if currentRate > g.targetFraudRate+2 {
			// Нужно меньше фрода
			isFraud = (riskScore > 85 && shouldBlock) && rand.Float64() < 0.5
		} else {
			isFraud = riskScore > 75 || shouldBlock
		}
	} else {
		isFraud = riskScore > 75 || shouldBlock
	}

	g.store.AddTransaction(userID, amount, riskScore, isFraud)

	if isFraud {
		alertMsg := fmt.Sprintf("Fraud: %s. Risk: %d. %s", userID, riskScore, message)
		g.store.AddAlert("Fraudulent Transaction", string(riskLevel), alertMsg)
	}

	if shouldBlock {
		g.store.AddLog("TRANSACTION_BLOCKED", fmt.Sprintf("Blocked transaction for %s: %s", userID, message))
	}
}

func (g *DataGenerator) createLog() {
	eventTypes := []string{
		"API_KEY_USED", "SESSION_CREATED", "RULE_EVALUATED",
		"RISK_SCORE_CALCULATED", "ALERT_TRIGGERED", "FRAUD_DETECTED", "IP_BLOCKED",
	}

	detailsList := []string{
		"API key validation passed",
		"New session created from IP",
		fmt.Sprintf("Rule #%d triggered", rand.Intn(100)),
		fmt.Sprintf("Risk score calculated: %d", rand.Intn(100)),
		"Alert sent to security team",
		"Fraud pattern detected",
		"IP from blocked country",
	}

	idx := rand.Intn(len(eventTypes))
	g.store.AddLog(eventTypes[idx], detailsList[idx])
}
