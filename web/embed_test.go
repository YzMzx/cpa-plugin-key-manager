package web

import (
	"strings"
	"testing"
)

// TestDashboardHTMLIsSelfContained pins the asset split: the served page must still
// be one document with every source inlined and no placeholder left behind.
func TestDashboardHTMLIsSelfContained(t *testing.T) {
	html := DashboardHTML()
	for _, placeholder := range []string{placeholderCSS, placeholderTheme, placeholderApp} {
		if strings.Contains(html, placeholder) {
			t.Fatalf("placeholder %q was not replaced", placeholder)
		}
	}
	for name, src := range map[string]string{"app.css": appCSS, "theme.js": themeJS, "runtime": runtimeJS(), "app.js": appJS} {
		if strings.TrimSpace(src) == "" {
			t.Fatalf("%s is empty", name)
		}
		if !strings.Contains(html, src) {
			t.Fatalf("%s was not inlined into the page", name)
		}
	}
	if strings.Count(html, "<script>") != 2 || strings.Count(html, "<style>") != 1 {
		t.Fatalf("unexpected number of inline blocks")
	}
	if strings.Contains(html, `src="app.js"`) || strings.Contains(html, `href="app.css"`) {
		t.Fatalf("page must not reference sibling asset URLs")
	}
}

func TestRuntimeModulesPrecedePageAndHaveNoExternalAssets(t *testing.T) {
	html := DashboardHTML()
	page := strings.Index(html, appJS)
	for _, name := range []string{"client.js", "state.js", "formatters.js", "auth.js", "events.js"} {
		raw, err := runtimeFiles.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		index := strings.Index(html, string(raw))
		if index < 0 || index >= page {
			t.Fatalf("%s must be inlined before page initialization", name)
		}
		if strings.Contains(html, "src=\""+name+"\"") {
			t.Fatalf("unexpected external module URL: %s", name)
		}
	}
	for _, legacy := range []string{"__reactFiber", "XMLHttpRequest.prototype", "writeCPAGlobalKeysSilent", "API_KEYS_SYNC"} {
		if strings.Contains(appJS, legacy) {
			t.Fatalf("legacy integration remains: %s", legacy)
		}
	}
}
