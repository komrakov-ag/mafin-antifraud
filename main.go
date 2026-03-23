package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"antifraud-system/internal/analytics"
	"antifraud-system/internal/generator"
	"antifraud-system/internal/geo"
	"antifraud-system/internal/notify"
	"antifraud-system/internal/reports"
	"antifraud-system/internal/rules"
	"antifraud-system/internal/storage"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var (
	store            *storage.Storage
	geoService       *geo.GeoService
	ruleEngine       *rules.RuleEngine
	notifyService    *notify.NotifyService
	reportGenerator  *reports.ReportGenerator
	analyticsService *analytics.AnalyticsService
)

// API ключи
var apiKeys = map[string]APIKey{}

type APIKey struct {
	ID       string
	Name     string
	IsActive bool
}

type User struct {
	APIKey   string
	FullName string
	Role     string
}

var users = map[string]User{}

func init() {
	// Постоянный API ключ
	const permanentKey = "magnat-anti-fraud-2024-secure-key"

	apiKeys[permanentKey] = APIKey{
		ID:       permanentKey,
		Name:     "Magnat Admin",
		IsActive: true,
	}
	users[permanentKey] = User{
		APIKey:   permanentKey,
		FullName: "Администратор Системы",
		Role:     "admin",
	}

	log.Printf("🔑 Permanent API Key: %s", permanentKey)
	log.Printf("📝 Use this key to login: %s", permanentKey)
}

func main() {
	// Определяем окружение
	environment := os.Getenv("ENVIRONMENT")
	if environment == "" {
		environment = "DEVELOPMENT"
	}
	log.Printf("🌍 Running in %s mode", environment)

	// Инициализация сервисов
	store = storage.NewStorageWithHistory(10)
	geoService = geo.NewGeoService()
	ruleEngine = rules.NewRuleEngine()
	notifyService = notify.NewNotifyService("", "")
	reportGenerator = &reports.ReportGenerator{}
	analyticsService = analytics.NewAnalyticsService(store)

	// Запуск генератора
	gen := generator.NewDataGenerator(store, geoService, ruleEngine)
	gen.StartWithTargetFraudRate(4.5)

	// Настройка роутера
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Статические файлы
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Публичные маршруты
	r.Get("/login", loginPageHandler)
	r.Post("/login", loginHandler)
	r.Get("/logout", logoutHandler)

	// Защищенные маршруты
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	r.Group(func(r chi.Router) {
		r.Use(apiKeyMiddleware)

		r.Get("/", dashboardHandler)
		r.Get("/reports", reportsPageHandler)
		r.Get("/settings", settingsPageHandler)

		r.Get("/api/metrics", metricsHandler)
		r.Get("/api/sessions", sessionsHandler)
		r.Get("/api/transactions", transactionsHandler)
		r.Get("/api/alerts", alertsHandler)
		r.Get("/api/logs", logsHandler)
		r.Post("/api/alerts/{id}/resolve", resolveAlertHandler)
		r.Post("/api/alerts/{id}/resolve-manual", resolveAlertManualHandler)
		r.Post("/api/simulate-attack", simulateAttackHandler)
		r.Post("/api/alerts/resolve-all", resolveAllAlertsHandler)

		r.Get("/api/trends", trendsHandler)
		r.Get("/api/risk-distribution", riskDistributionHandler)
		r.Get("/api/heatmap", heatmapHandler)
		r.Get("/api/geo-stats", geoStatsHandler)
		r.Get("/api/city-stats", cityStatsHandler)
		r.Get("/api/hourly-activity", hourlyActivityHandler)

		r.Get("/api/sessions/filter", sessionsFilterHandler)
		r.Get("/api/transactions/filter", transactionsFilterHandler)
		r.Get("/api/alerts/filter", alertsFilterHandler)

		r.Post("/api/reports/generate", generateReportHandler)
		r.Get("/api/reports/download/{filename}", downloadReportHandler)

		r.Get("/api/rules", rulesHandler)
		r.Post("/api/rules/{id}/toggle", toggleRuleHandler)
		r.Get("/api/notifications", notificationsHandler)
		r.Post("/api/notifications/{id}/toggle", toggleNotificationHandler)
	})

	port := "8080"
	log.Printf("🚀 MAFIN Server starting on http://localhost:%s", port)
	log.Printf("📊 Open http://localhost:%s/login to get started", port)

	http.ListenAndServe(":"+port, r)
}

func apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var apiKey string

		if cookie, err := r.Cookie("api_key"); err == nil {
			apiKey = cookie.Value
		}

		if apiKey == "" {
			apiKey = r.Header.Get("X-API-Key")
		}

		if apiKey == "" {
			if r.Header.Get("HX-Request") == "true" {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`<div class="error">❌ Session expired. <a href="/login">Login</a></div>`))
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		keyInfo, exists := apiKeys[apiKey]
		if !exists || !keyInfo.IsActive {
			http.Redirect(w, r, "/login?error=Invalid API key", http.StatusSeeOther)
			return
		}

		user, _ := users[apiKey]
		ctx := context.WithValue(r.Context(), "user_name", keyInfo.Name)
		ctx = context.WithValue(ctx, "user_fullname", user.FullName)
		ctx = context.WithValue(ctx, "user_role", user.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MAFIN - Magnat Anti-Fraud Inspector</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            border-radius: 24px;
            padding: 48px;
            width: 100%;
            max-width: 480px;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
        }
        .logo {
            margin-bottom: 32px;
        }
        .logo-img {
            width: 100px;
            height: 100px;
            margin: 0 auto 20px;
            animation: fadeIn 0.5s ease;
        }
        .logo-img img {
            width: 100%;
            height: 100%;
            object-fit: contain;
        }
        .logo h1 {
            color: #dc2626;
            font-size: 28px;
            margin-bottom: 8px;
        }
        .logo p {
            color: #666;
            font-size: 14px;
        }
        .api-key-input {
            width: 100%;
            padding: 14px;
            border: 2px solid #e5e7eb;
            border-radius: 12px;
            font-family: monospace;
            font-size: 14px;
            margin: 20px 0;
            transition: all 0.2s;
        }
        .api-key-input:focus {
            outline: none;
            border-color: #dc2626;
            box-shadow: 0 0 0 3px rgba(220,38,38,0.1);
        }
        button {
            width: 100%;
            background: #dc2626;
            color: white;
            border: none;
            padding: 14px;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        button:hover {
            background: #b91c1c;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(220,38,38,0.3);
        }
        .info {
            margin-top: 24px;
            padding: 16px;
            background: #f3f4f6;
            border-radius: 12px;
            font-size: 13px;
            color: #666;
        }
        .error {
            background: #fee2e2;
            color: #dc2626;
            padding: 12px;
            border-radius: 12px;
            margin-bottom: 20px;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.9); }
            to { opacity: 1; transform: scale(1); }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <div class="logo-img">
                <img src="/static/img/magnit-logo.png" alt="Magnit">
            </div>
            <h1>MAFIN</h1>
            <p>Magnat Anti-Fraud Inspector</p>
        </div>
        {{if .Error}}<div class="error">❌ {{.Error}}</div>{{end}}
        <form method="POST" action="/login">
            <input type="text" name="api_key" class="api-key-input" placeholder="Введите API ключ" autofocus>
            <button type="submit">🔑 Войти в систему</button>
        </form>
        <div class="info">
            <strong>📋 Для получения API ключа</strong><br>
            обратитесь в службу поддержки<br>
            <span style="color:#dc2626;">support@magnat.ru</span>
        </div>
    </div>
</body>
</html>`
	t, _ := template.New("login").Parse(tmpl)
	t.Execute(w, map[string]interface{}{"Error": r.URL.Query().Get("error")})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	apiKey := r.FormValue("api_key")
	if apiKey == "" {
		http.Redirect(w, r, "/login?error=Введите API ключ", http.StatusSeeOther)
		return
	}
	if _, exists := apiKeys[apiKey]; !exists {
		http.Redirect(w, r, "/login?error=Неверный API ключ", http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "api_key", Value: apiKey, Path: "/", MaxAge: 86400, HttpOnly: true})
	store.AddLog("USER_LOGIN", "User logged in")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "api_key", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/dashboard.html"))

	// Определяем окружение (можно сделать настраиваемым через переменную окружения)
	environment := "PRODUCTION"
	// Или для тестирования: environment := "TEST"

	tmpl.Execute(w, map[string]interface{}{
		"ActiveSessions":    store.GetActiveSessions(),
		"TotalTransactions": store.GetTotalTransactions(),
		"ActiveAlerts":      store.GetActiveAlerts(),
		"FraudRate":         fmt.Sprintf("%.1f", store.GetFraudRate()),
		"Environment":       environment,
	})
}

func reportsPageHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/reports.html"))
	tmpl.Execute(w, nil)
}

func settingsPageHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/settings.html"))
	tmpl.Execute(w, map[string]interface{}{
		"Rules":         ruleEngine.GetRules(),
		"Notifications": notifyService.GetNotifications(),
	})
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"active_sessions":    store.GetActiveSessions(),
		"total_transactions": store.GetTotalTransactions(),
		"active_alerts":      store.GetActiveAlerts(),
		"fraud_rate":         store.GetFraudRate(),
	})
}

func trendsHandler(w http.ResponseWriter, r *http.Request) {
	days := 10
	json.NewEncoder(w).Encode(analyticsService.GetTrendsByDays(days))
}

func riskDistributionHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(analyticsService.GetRiskDistribution())
}

func heatmapHandler(w http.ResponseWriter, r *http.Request) {
	sessions := store.GetSessions(1000)
	ips := make([]string, len(sessions))
	for i, s := range sessions {
		ips[i] = s.IP
	}
	json.NewEncoder(w).Encode(geoService.GetHeatmapData(ips))
}

func geoStatsHandler(w http.ResponseWriter, r *http.Request) {
	sessions := store.GetSessions(1000)
	ips := make([]string, len(sessions))
	for i, s := range sessions {
		ips[i] = s.IP
	}
	json.NewEncoder(w).Encode(geoService.GetCountryStats(ips))
}

func cityStatsHandler(w http.ResponseWriter, r *http.Request) {
	sessions := store.GetSessions(1000)
	cityStats := make(map[string]int)

	for _, s := range sessions {
		info := geoService.GetGeoInfo(s.IP)
		if info.City != "" && info.City != "Unknown" {
			cityStats[info.City]++
		}
	}

	// Добавляем российские города по умолчанию для демонстрации
	if len(cityStats) == 0 {
		cityStats["Москва"] = 15
		cityStats["Санкт-Петербург"] = 8
		cityStats["Новосибирск"] = 5
		cityStats["Екатеринбург"] = 4
		cityStats["Казань"] = 3
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cityStats)
}

func hourlyActivityHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(analyticsService.GetHourlyActivity())
}

func sessionsHandler(w http.ResponseWriter, r *http.Request) {
	sessions := store.GetSessions(50)
	var html strings.Builder
	html.WriteString(`<table class="data-table"><thead> <th>ID</th><th>User ID</th><th>IP</th><th>Risk Score</th><th>Status</th><th>Created At</th> </thead><tbody>`)
	for _, s := range sessions {
		riskColor := "#10b981"
		if s.RiskScore > 80 {
			riskColor = "#dc2626"
		} else if s.RiskScore > 50 {
			riskColor = "#f59e0b"
		}
		html.WriteString(fmt.Sprintf(`<tr><td>%d</td><td>%s</td><td>%s</td><td style="color:%s">%d</td><td>%s</td><td>%s</td></tr>`,
			s.ID, s.UserID, s.IP, riskColor, s.RiskScore, s.Status, s.CreatedAt.Format("2006-01-02 15:04:05")))
	}
	html.WriteString(`</tbody></table>`)
	w.Write([]byte(html.String()))
}

func sessionsFilterHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	ip := r.URL.Query().Get("ip")
	status := r.URL.Query().Get("status")
	sessions := store.GetSessionsFiltered(userID, ip, status)
	var html strings.Builder
	html.WriteString(`<table class="data-table"><thead><th>ID</th><th>User ID</th><th>IP</th><th>Risk Score</th><th>Status</th><th>Created At</th></thead><tbody>`)
	for _, s := range sessions {
		riskColor := "#10b981"
		if s.RiskScore > 80 {
			riskColor = "#dc2626"
		} else if s.RiskScore > 50 {
			riskColor = "#f59e0b"
		}
		html.WriteString(fmt.Sprintf(`<tr><td>%d</td><td>%s</td><td>%s</td><td style="color:%s">%d</td><td>%s</td><td>%s</td></tr>`,
			s.ID, s.UserID, s.IP, riskColor, s.RiskScore, s.Status, s.CreatedAt.Format("2006-01-02 15:04:05")))
	}
	html.WriteString(`</tbody></table>`)
	w.Write([]byte(html.String()))
}

func transactionsHandler(w http.ResponseWriter, r *http.Request) {
	transactions := store.GetTransactions(50)
	var html strings.Builder
	html.WriteString(`<table class="data-table"><thead><th>ID</th><th>User ID</th><th>Amount</th><th>Risk Score</th><th>Status</th><th>Created At</th></thead><tbody>`)
	for _, t := range transactions {
		status := "✅ Normal"
		statusColor := "#10b981"
		if t.IsFraud {
			status = "⚠️ FRAUD"
			statusColor = "#dc2626"
		}
		riskColor := "#10b981"
		if t.RiskScore > 80 {
			riskColor = "#dc2626"
		} else if t.RiskScore > 50 {
			riskColor = "#f59e0b"
		}
		html.WriteString(fmt.Sprintf(`<tr><td>%d</td><td>%s</td><td>%.2f ₽</td><td style="color:%s">%d</td><td style="color:%s">%s</td><td>%s</td></tr>`,
			t.ID, t.UserID, t.Amount, riskColor, t.RiskScore, statusColor, status, t.CreatedAt.Format("2006-01-02 15:04:05")))
	}
	html.WriteString(`</tbody></table>`)
	w.Write([]byte(html.String()))
}

func transactionsFilterHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	status := r.URL.Query().Get("status")
	dateFrom := r.URL.Query().Get("date_from")
	dateTo := r.URL.Query().Get("date_to")
	minAmount, _ := strconv.ParseFloat(r.URL.Query().Get("min_amount"), 64)
	maxAmount, _ := strconv.ParseFloat(r.URL.Query().Get("max_amount"), 64)

	transactions := store.GetTransactionsFiltered(userID, status, dateFrom, dateTo, minAmount, maxAmount)
	var html strings.Builder
	html.WriteString(`<table class="data-table"><thead><th>ID</th><th>User ID</th><th>Amount</th><th>Risk Score</th><th>Status</th><th>Created At</th></thead><tbody>`)
	for _, t := range transactions {
		statusText := "✅ Normal"
		statusColor := "#10b981"
		if t.IsFraud {
			statusText = "⚠️ FRAUD"
			statusColor = "#dc2626"
		}
		riskColor := "#10b981"
		if t.RiskScore > 80 {
			riskColor = "#dc2626"
		} else if t.RiskScore > 50 {
			riskColor = "#f59e0b"
		}
		html.WriteString(fmt.Sprintf(`<tr><td>%d</td><td>%s</td><td>%.2f ₽</td><td style="color:%s">%d</td><td style="color:%s">%s</td><td>%s</td></tr>`,
			t.ID, t.UserID, t.Amount, riskColor, t.RiskScore, statusColor, statusText, t.CreatedAt.Format("2006-01-02 15:04:05")))
	}
	html.WriteString(`</tbody></table>`)
	w.Write([]byte(html.String()))
}

func alertsHandler(w http.ResponseWriter, r *http.Request) {
	alerts := store.GetAlerts(50)
	var html strings.Builder
	html.WriteString(`<div class="alerts-container">`)
	for _, a := range alerts {
		resolvedClass := ""
		resolvedBadge := ""
		if a.Resolved {
			resolvedClass = "opacity-50"
			if a.ResolvedBy != "" {
				resolvedBadge = fmt.Sprintf("<div class='resolved-badge'>✓ Решен: %s %s</div>", a.ResolvedBy, a.ResolvedAt.Format("2006-01-02 15:04"))
			} else {
				resolvedBadge = "<div class='resolved-badge'>✓ Авто-решен</div>"
			}
		}
		severityClass := "severity-" + a.Severity
		html.WriteString(fmt.Sprintf(`<div class="alert-card %s" id="alert-%d">
			<div class="alert-header"><div><span class="alert-type">%s</span><span class="alert-severity %s">%s</span></div><span>%s</span></div>
			<div>%s</div>%s`, resolvedClass, a.ID, a.Type, severityClass, strings.ToUpper(a.Severity), a.CreatedAt.Format("2006-01-02 15:04:05"), a.Message, resolvedBadge))
		if !a.Resolved {
			html.WriteString(`<button class="resolve-manual-btn" onclick="resolveAlert(` + fmt.Sprintf("%d", a.ID) + `, 'Сотрудник')">✋ Решить вручную</button>`)
		}
		html.WriteString(`</div>`)
	}
	html.WriteString(`</div><script>function resolveAlert(id, name){fetch('/api/alerts/'+id+'/resolve-manual?user='+encodeURIComponent(name),{method:"POST"}).then(()=>location.reload());}</script>`)
	w.Write([]byte(html.String()))
}

func alertsFilterHandler(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")
	resolved := r.URL.Query().Get("resolved")
	alerts := store.GetAlertsFiltered(severity, resolved)
	var html strings.Builder
	html.WriteString(`<div class="alerts-container">`)
	for _, a := range alerts {
		resolvedClass := ""
		resolvedBadge := ""
		if a.Resolved {
			resolvedClass = "opacity-50"
			if a.ResolvedBy != "" {
				resolvedBadge = fmt.Sprintf("<div class='resolved-badge'>✓ Решен: %s %s</div>", a.ResolvedBy, a.ResolvedAt.Format("2006-01-02 15:04"))
			} else {
				resolvedBadge = "<div class='resolved-badge'>✓ Авто-решен</div>"
			}
		}
		severityClass := "severity-" + a.Severity
		html.WriteString(fmt.Sprintf(`<div class="alert-card %s" id="alert-%d">
			<div class="alert-header"><div><span class="alert-type">%s</span><span class="alert-severity %s">%s</span></div><span>%s</span></div>
			<div>%s</div>%s`, resolvedClass, a.ID, a.Type, severityClass, strings.ToUpper(a.Severity), a.CreatedAt.Format("2006-01-02 15:04:05"), a.Message, resolvedBadge))
		if !a.Resolved {
			html.WriteString(`<button class="resolve-manual-btn" onclick="resolveAlert(` + fmt.Sprintf("%d", a.ID) + `, 'Сотрудник')">✋ Решить вручную</button>`)
		}
		html.WriteString(`</div>`)
	}
	html.WriteString(`</div>`)
	w.Write([]byte(html.String()))
}

func resolveAlertHandler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	store.ResolveAlertAuto(id)
	w.Write([]byte(""))
}

func resolveAlertManualHandler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	userName := r.URL.Query().Get("user")
	if userName == "" {
		userName = "Сотрудник"
	}
	store.ResolveAlertManual(id, userName)
	w.Write([]byte(""))
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	logs := store.GetLogs(100)
	var html strings.Builder
	html.WriteString(`<div class="logs-container">`)
	for _, l := range logs {
		html.WriteString(fmt.Sprintf(`<div class="log-entry"><span class="log-time">[%s]</span><span class="log-event">%s</span><span> - %s</span></div>`,
			l.CreatedAt.Format("2006-01-02 15:04:05"), l.EventType, l.Details))
	}
	html.WriteString(`</div>`)
	w.Write([]byte(html.String()))
}

func generateReportHandler(w http.ResponseWriter, r *http.Request) {
	format := r.FormValue("format")
	startDate := r.FormValue("start_date")
	endDate := r.FormValue("end_date")

	transactionsData := store.GetTransactionsFiltered("", "", startDate, endDate, 0, 0)
	reportsMap := make(map[string]*reports.TransactionReport)

	for _, t := range transactionsData {
		dateKey := t.CreatedAt.Format("2006-01-02")
		if _, ok := reportsMap[dateKey]; !ok {
			reportsMap[dateKey] = &reports.TransactionReport{Date: dateKey}
		}
		report := reportsMap[dateKey]
		report.TotalCount++
		report.TotalAmount += t.Amount
		report.AvgRiskScore += float64(t.RiskScore)
		if t.IsFraud {
			report.FraudCount++
			report.FraudAmount += t.Amount
		}
	}

	reportList := make([]reports.TransactionReport, 0, len(reportsMap))
	for _, r := range reportsMap {
		if r.TotalCount > 0 {
			r.FraudRate = float64(r.FraudCount) / float64(r.TotalCount) * 100
			r.AvgRiskScore = r.AvgRiskScore / float64(r.TotalCount)
		}
		reportList = append(reportList, *r)
	}

	var filename string
	var err error
	switch format {
	case "pdf":
		filename, err = reportGenerator.GeneratePDF(reportList, startDate, endDate)
	case "excel":
		filename, err = reportGenerator.GenerateExcel(reportList)
	default:
		filename, err = reportGenerator.GenerateCSV(reportList)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"filename": filename})
}

func downloadReportHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, chi.URLParam(r, "filename"))
}

func rulesHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(ruleEngine.GetRules())
}

func toggleRuleHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	enabled := r.FormValue("enabled") == "true"
	weight, _ := strconv.Atoi(r.FormValue("weight"))
	ruleEngine.UpdateRule(id, enabled, weight)
	w.WriteHeader(http.StatusOK)
}

func notificationsHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(notifyService.GetNotifications())
}

func toggleNotificationHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	enabled := r.FormValue("enabled") == "true"
	notifyService.UpdateNotification(id, enabled)
	w.WriteHeader(http.StatusOK)
}

func simulateAttackHandler(w http.ResponseWriter, r *http.Request) {
	for i := 0; i < 10; i++ {
		userID := fmt.Sprintf("attacker_%03d", i)
		amount := float64(500 + randInt(0, 4500))
		riskScore := randInt(90, 100)
		ip := fmt.Sprintf("185.130.5.%d", randInt(1, 255))

		if geoService.IsIPBlocked(ip) {
			store.AddLog("IP_BLOCKED", fmt.Sprintf("Blocked IP %s from %s", ip, userID))
		}
		store.AddTransaction(userID, amount, riskScore, true)
	}
	store.AddAlert("Massive Fraud Attack", "critical", "10 fraudulent transactions detected")
	store.AddLog("ATTACK_SIMULATED", "User triggered fraud attack simulation")

	notifyService.SendAlert(notify.AlertNotification{
		Type:      "Massive Fraud Attack",
		Severity:  "critical",
		Message:   "10 fraudulent transactions detected",
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
	})

	w.Header().Set("HX-Trigger", `{"attackSimulated": true, "playSound": true}`)
	w.Write([]byte("Attack simulated"))
}

func randInt(min, max int) int {
	return min + int(time.Now().UnixNano())%(max-min+1)
}

// ResolveAllAlertsHandler закрывает все активные алерты
func resolveAllAlertsHandler(w http.ResponseWriter, r *http.Request) {
	count := store.ResolveAllAlerts()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"resolved": count,
		"message":  fmt.Sprintf("Resolved %d alerts", count),
	})
}
