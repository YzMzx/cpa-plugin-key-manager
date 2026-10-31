package sqlitestore

import "time"

func timeNowMillis() int64 { return time.Now().UnixMilli() }
