package web

import _ "embed"

//go:embed index.html
var indexHTML string

// DashboardHTML returns the embedded Single-Page Application HTML for the plugin management and self-service UI.
func DashboardHTML() string {
	return indexHTML
}
