package usage

import "database/sql"

func loadQuotaFromDB(conn *sql.DB) (map[string]int64, error) {
	rows, err := conn.Query("SELECT api_key,total_cost_nano_usd FROM quota_usage")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	costs := make(map[string]int64)
	for rows.Next() {
		var key string
		var cost int64
		if err := rows.Scan(&key, &cost); err != nil {
			return nil, err
		}
		costs[key] = cost
	}
	return costs, rows.Err()
}
