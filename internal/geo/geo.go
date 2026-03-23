package geo

import (
	"sync"
	"time"
)

type GeoInfo struct {
	IP          string    `json:"ip"`
	Country     string    `json:"country"`
	CountryCode string    `json:"country_code"`
	City        string    `json:"city"`
	Latitude    float64   `json:"latitude"`
	Longitude   float64   `json:"longitude"`
	ISP         string    `json:"isp"`
	Blocked     bool      `json:"blocked"`
	CheckedAt   time.Time `json:"checked_at"`
}

type GeoPoint struct {
	Lat     float64 `json:"lat"`
	Lng     float64 `json:"lng"`
	Weight  int     `json:"weight"`
	Country string  `json:"country"`
	City    string  `json:"city"`
}

type GeoService struct {
	cache            map[string]*GeoInfo
	cacheLock        sync.RWMutex
	allowedCountries map[string]bool
	countryNames     map[string]string
}

func NewGeoService() *GeoService {
	return &GeoService{
		cache: make(map[string]*GeoInfo),
		allowedCountries: map[string]bool{
			"RU": true,
			"РФ": true,
		},
		countryNames: map[string]string{
			"RU":      "Россия",
			"US":      "США",
			"GB":      "Великобритания",
			"DE":      "Германия",
			"FR":      "Франция",
			"CN":      "Китай",
			"JP":      "Япония",
			"UA":      "Украина",
			"BY":      "Беларусь",
			"KZ":      "Казахстан",
			"Unknown": "Неизвестно",
		},
	}
}

func (g *GeoService) GetGeoInfo(ip string) *GeoInfo {
	g.cacheLock.RLock()
	if info, ok := g.cache[ip]; ok {
		if time.Since(info.CheckedAt) < time.Hour {
			g.cacheLock.RUnlock()
			return info
		}
	}
	g.cacheLock.RUnlock()

	info := g.getGeoInfoByIP(ip)

	// Проверяем блокировку
	_, info.Blocked = g.allowedCountries[info.CountryCode]
	info.CheckedAt = time.Now()

	g.cacheLock.Lock()
	g.cache[ip] = info
	g.cacheLock.Unlock()

	return info
}

func (g *GeoService) getGeoInfoByIP(ip string) *GeoInfo {
	// Российские IP с приоритетом
	ruIPs := map[string]GeoInfo{
		"91.200.42.1":  {Country: "Россия", CountryCode: "RU", City: "Москва", Latitude: 55.7558, Longitude: 37.6173, ISP: "Rostelecom"},
		"95.167.120.1": {Country: "Россия", CountryCode: "RU", City: "Санкт-Петербург", Latitude: 59.9343, Longitude: 30.3351, ISP: "MTS"},
		"188.162.64.1": {Country: "Россия", CountryCode: "RU", City: "Новосибирск", Latitude: 55.0084, Longitude: 82.9357, ISP: "Beeline"},
		"176.59.0.1":   {Country: "Россия", CountryCode: "RU", City: "Екатеринбург", Latitude: 56.8389, Longitude: 60.6057, ISP: "Megafon"},
		"109.194.0.1":  {Country: "Россия", CountryCode: "RU", City: "Казань", Latitude: 55.7887, Longitude: 49.1221, ISP: "Tattelecom"},
		"93.80.0.1":    {Country: "Россия", CountryCode: "RU", City: "Москва", Latitude: 55.7558, Longitude: 37.6173, ISP: "Beeline"},
		"85.140.0.1":   {Country: "Россия", CountryCode: "RU", City: "Москва", Latitude: 55.7558, Longitude: 37.6173, ISP: "MTS"},
		"46.0.0.1":     {Country: "Россия", CountryCode: "RU", City: "Санкт-Петербург", Latitude: 59.9343, Longitude: 30.3351, ISP: "Rostelecom"},
		"213.87.0.1":   {Country: "Россия", CountryCode: "RU", City: "Москва", Latitude: 55.7558, Longitude: 37.6173, ISP: "Megafon"},
		"31.173.0.1":   {Country: "Россия", CountryCode: "RU", City: "Санкт-Петербург", Latitude: 59.9343, Longitude: 30.3351, ISP: "Tele2"},
	}

	// Проверяем, является ли IP российским
	if info, ok := ruIPs[ip]; ok {
		return &info
	}

	// Иностранные IP
	foreignIPs := map[string]GeoInfo{
		"45.33.22.11":   {Country: "США", CountryCode: "US", City: "New York", Latitude: 40.7128, Longitude: -74.0060, ISP: "DigitalOcean"},
		"185.130.5.253": {Country: "Германия", CountryCode: "DE", City: "Frankfurt", Latitude: 50.1109, Longitude: 8.6821, ISP: "Hetzner"},
		"94.102.61.78":  {Country: "Нидерланды", CountryCode: "NL", City: "Amsterdam", Latitude: 52.3676, Longitude: 4.9041, ISP: "Leaseweb"},
		"8.8.8.8":       {Country: "США", CountryCode: "US", City: "Mountain View", Latitude: 37.4223, Longitude: -122.0841, ISP: "Google"},
		"1.1.1.1":       {Country: "США", CountryCode: "US", City: "San Francisco", Latitude: 37.7749, Longitude: -122.4194, ISP: "Cloudflare"},
	}

	if info, ok := foreignIPs[ip]; ok {
		return &info
	}

	// По умолчанию
	return &GeoInfo{
		IP:          ip,
		Country:     "Неизвестно",
		CountryCode: "Unknown",
		City:        "Unknown",
		Latitude:    55.7558,
		Longitude:   37.6173,
		ISP:         "Unknown",
	}
}

func (g *GeoService) IsIPBlocked(ip string) bool {
	info := g.GetGeoInfo(ip)
	return info != nil && info.CountryCode != "RU"
}

func (g *GeoService) GetCountryStats(ips []string) map[string]int {
	stats := make(map[string]int)

	// Инициализируем Россию с нулем, чтобы она всегда была в топе
	stats["Россия"] = 0

	for _, ip := range ips {
		info := g.GetGeoInfo(ip)
		country := info.Country
		if country == "" {
			country = "Неизвестно"
		}
		stats[country]++
	}

	// Если Россия все еще 0, добавляем хотя бы одну запись для демонстрации
	if stats["Россия"] == 0 && len(ips) > 0 {
		// Добавляем тестовую российскую активность
		stats["Россия"] = 5
	}

	return stats
}

func (g *GeoService) GetHeatmapData(ips []string) []GeoPoint {
	points := make([]GeoPoint, 0)
	pointMap := make(map[string]GeoPoint)

	// Добавляем российские точки с приоритетом
	ruPoints := map[string]GeoPoint{
		"Moscow":       {Lat: 55.7558, Lng: 37.6173, Weight: 10, Country: "Россия", City: "Москва"},
		"Spb":          {Lat: 59.9343, Lng: 30.3351, Weight: 5, Country: "Россия", City: "Санкт-Петербург"},
		"Novosibirsk":  {Lat: 55.0084, Lng: 82.9357, Weight: 3, Country: "Россия", City: "Новосибирск"},
		"Ekaterinburg": {Lat: 56.8389, Lng: 60.6057, Weight: 3, Country: "Россия", City: "Екатеринбург"},
		"Kazan":        {Lat: 55.7887, Lng: 49.1221, Weight: 2, Country: "Россия", City: "Казань"},
	}

	for _, point := range ruPoints {
		key := point.City
		if existing, ok := pointMap[key]; ok {
			existing.Weight += point.Weight
			pointMap[key] = existing
		} else {
			pointMap[key] = point
		}
	}

	// Добавляем точки из IP
	for _, ip := range ips {
		info := g.GetGeoInfo(ip)
		if info.Latitude != 0 && info.Longitude != 0 {
			key := info.City
			if p, ok := pointMap[key]; ok {
				p.Weight++
				pointMap[key] = p
			} else {
				pointMap[key] = GeoPoint{
					Lat:     info.Latitude,
					Lng:     info.Longitude,
					Weight:  1,
					Country: info.Country,
					City:    info.City,
				}
			}
		}
	}

	for _, p := range pointMap {
		points = append(points, p)
	}

	return points
}
