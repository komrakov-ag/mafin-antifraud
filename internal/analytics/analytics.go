package analytics

import (
	"sort"
	"time"

	"antifraud-system/internal/storage"
)

type TrendPoint struct {
	Date      string  `json:"date"`
	FraudRate float64 `json:"fraud_rate"`
	Count     int     `json:"count"`
}

type RiskDistribution struct {
	Low      int `json:"low"`
	Medium   int `json:"medium"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}

type AnalyticsService struct {
	store *storage.Storage
}

func NewAnalyticsService(store *storage.Storage) *AnalyticsService {
	return &AnalyticsService{store: store}
}

func (a *AnalyticsService) GetTrendsByDays(days int) []TrendPoint {
	transactions := a.store.GetTransactions(10000)

	trends := make(map[string]*TrendPoint)
	cutoff := time.Now().AddDate(0, 0, -days)

	for _, tx := range transactions {
		if tx.CreatedAt.Before(cutoff) {
			continue
		}

		dateKey := tx.CreatedAt.Format("2006-01-02")
		if _, ok := trends[dateKey]; !ok {
			trends[dateKey] = &TrendPoint{Date: dateKey, FraudRate: 0, Count: 0}
		}

		trends[dateKey].Count++
		if tx.IsFraud {
			trends[dateKey].FraudRate++
		}
	}

	result := make([]TrendPoint, 0, len(trends))
	for _, t := range trends {
		if t.Count > 0 {
			t.FraudRate = (t.FraudRate / float64(t.Count)) * 100
		}
		result = append(result, *t)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Date < result[j].Date
	})

	return result
}

func (a *AnalyticsService) GetTrends(hours int) []TrendPoint {
	transactions := a.store.GetTransactions(10000)

	trends := make(map[string]*TrendPoint)
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	for _, tx := range transactions {
		if tx.CreatedAt.Before(cutoff) {
			continue
		}

		hourKey := tx.CreatedAt.Format("2006-01-02 15:00")
		if _, ok := trends[hourKey]; !ok {
			trends[hourKey] = &TrendPoint{Date: hourKey, FraudRate: 0, Count: 0}
		}

		trends[hourKey].Count++
		if tx.IsFraud {
			trends[hourKey].FraudRate++
		}
	}

	result := make([]TrendPoint, 0, len(trends))
	for _, t := range trends {
		if t.Count > 0 {
			t.FraudRate = (t.FraudRate / float64(t.Count)) * 100
		}
		result = append(result, *t)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Date < result[j].Date
	})

	return result
}

func (a *AnalyticsService) GetRiskDistribution() RiskDistribution {
	sessions := a.store.GetSessions(10000)

	dist := RiskDistribution{}
	for _, s := range sessions {
		switch {
		case s.RiskScore > 80:
			dist.Critical++
		case s.RiskScore > 60:
			dist.High++
		case s.RiskScore > 30:
			dist.Medium++
		default:
			dist.Low++
		}
	}

	return dist
}

func (a *AnalyticsService) GetHourlyActivity() map[int]int {
	transactions := a.store.GetTransactions(10000)
	activity := make(map[int]int)

	for _, tx := range transactions {
		hour := tx.CreatedAt.Hour()
		activity[hour]++
	}

	return activity
}
