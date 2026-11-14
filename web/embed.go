package web

import (
	"embed"
	"strings"
)

// The admin UI is authored as separate files (markup, styles, scripts) for
// maintainability, but it is served as ONE self-contained HTML document: CPA mounts
// plugin resources under a single route, so the page must not depend on sibling
// asset URLs. The sources are stitched together once at init.

//go:embed index.html
var shellHTML string

//go:embed app.css
var appCSS string

//go:embed theme.js
var themeJS string

//go:embed app.js
var appJS string

//go:embed client.js state.js formatters.js auth.js events.js dialogs.js cleanup-jobs.js audit.js settings.js
var runtimeFiles embed.FS

const (
	placeholderCSS   = "/*@@APP_CSS@@*/"
	placeholderTheme = "/*@@THEME_JS@@*/"
	placeholderApp   = "/*@@APP_JS@@*/"
)

var indexHTML = assemble()

func runtimeJS() string {
	var sources []string
	for _, name := range []string{"client.js", "state.js", "formatters.js", "auth.js", "events.js", "dialogs.js", "cleanup-jobs.js", "audit.js", "settings.js"} {
		raw, err := runtimeFiles.ReadFile(name)
		if err != nil {
			panic(err)
		}
		sources = append(sources, string(raw))
	}
	return strings.Join(sources, "\n")
}

func assemble() string {
	// strings.NewReplacer performs a single pass, so content inside the CSS/JS can
	// never be mistaken for another placeholder.
	return strings.NewReplacer(
		placeholderCSS, appCSS,
		placeholderTheme, themeJS,
		placeholderApp, runtimeJS()+"\n"+appJS,
	).Replace(shellHTML)
}

// DashboardHTML returns the embedded Single-Page Application HTML for the plugin management and self-service UI.
func DashboardHTML() string {
	return indexHTML
}
