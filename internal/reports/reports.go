package reports

import (
	"encoding/csv"
	"fmt"
	"os"
	"time"
)

type TransactionReport struct {
	Date         string
	TotalCount   int
	FraudCount   int
	FraudRate    float64
	TotalAmount  float64
	FraudAmount  float64
	AvgRiskScore float64
}

type ReportGenerator struct{}

func (rg *ReportGenerator) GeneratePDF(reports []TransactionReport, startDate, endDate string) (string, error) {
	filename := fmt.Sprintf("reports/fraud_report_%s.pdf", time.Now().Format("20060102_150405"))
	// Создаем директорию если нет
	os.MkdirAll("reports", 0755)

	// Заглушка - в реальном проекте здесь генерация PDF
	f, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	f.WriteString(fmt.Sprintf("Fraud Report %s - %s\n", startDate, endDate))
	for _, r := range reports {
		f.WriteString(fmt.Sprintf("%s: %d transactions, %.1f%% fraud rate\n", r.Date, r.TotalCount, r.FraudRate))
	}

	return filename, nil
}

func (rg *ReportGenerator) GenerateCSV(reports []TransactionReport) (string, error) {
	filename := fmt.Sprintf("reports/fraud_report_%s.csv", time.Now().Format("20060102_150405"))
	os.MkdirAll("reports", 0755)

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Дата", "Всего транзакций", "Мошеннических", "% Фрода", "Общая сумма", "Сумма фрода", "Средний риск"}
	writer.Write(headers)

	for _, r := range reports {
		row := []string{
			r.Date,
			fmt.Sprintf("%d", r.TotalCount),
			fmt.Sprintf("%d", r.FraudCount),
			fmt.Sprintf("%.1f", r.FraudRate),
			fmt.Sprintf("%.2f", r.TotalAmount),
			fmt.Sprintf("%.2f", r.FraudAmount),
			fmt.Sprintf("%.1f", r.AvgRiskScore),
		}
		writer.Write(row)
	}

	return filename, nil
}

func (rg *ReportGenerator) GenerateExcel(reports []TransactionReport) (string, error) {
	// Для простоты используем CSV как Excel (можно открыть в Excel)
	// В реальном проекте используйте библиотеку excelize
	filename := fmt.Sprintf("reports/fraud_report_%s.csv", time.Now().Format("20060102_150405"))
	os.MkdirAll("reports", 0755)

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"Дата", "Всего транзакций", "Мошеннических", "% Фрода", "Общая сумма", "Сумма фрода", "Средний риск"}
	writer.Write(headers)

	for _, r := range reports {
		row := []string{
			r.Date,
			fmt.Sprintf("%d", r.TotalCount),
			fmt.Sprintf("%d", r.FraudCount),
			fmt.Sprintf("%.1f", r.FraudRate),
			fmt.Sprintf("%.2f", r.TotalAmount),
			fmt.Sprintf("%.2f", r.FraudAmount),
			fmt.Sprintf("%.1f", r.AvgRiskScore),
		}
		writer.Write(row)
	}

	return filename, nil
}
