package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type workflowStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	With map[string]any    `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}
type workflowJob struct {
	Needs       any               `yaml:"needs"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
}

func TestReleaseWorkflowUsesImmutableVersionMatchedInputs(t *testing.T) {
	raw, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Permissions map[string]string      `yaml:"permissions"`
		Jobs        map[string]workflowJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	if workflow.Permissions["contents"] != "read" {
		t.Fatal("non-release jobs must not inherit contents write")
	}
	resolve, ok := workflow.Jobs["resolve"]
	if !ok {
		t.Fatal("missing immutable release resolver")
	}
	var resolver workflowStep
	for _, step := range resolve.Steps {
		if step.Run != "" {
			resolver = step
		}
	}
	for _, guard := range []string{"git show-ref --verify", "refs/tags/$TAG^{commit}", "PluginVersion", "Release tag does not match", "GITHUB_REF_TYPE", "681ce41b6e44c45b15b79378b003909d6ba29e68"} {
		if !strings.Contains(resolver.Run, guard) {
			t.Fatalf("missing resolver guard %q", guard)
		}
	}
	if resolver.Env["INPUT_TAG"] != "${{ github.event.inputs.tag_name }}" || strings.Contains(resolver.Run, "${{ github.event.inputs.tag_name }}") {
		t.Fatal("manual input must enter through an environment variable")
	}
	for _, name := range []string{"test", "build"} {
		job, ok := workflow.Jobs[name]
		if !ok {
			t.Fatalf("missing %s job", name)
		}
		plugin, host := false, false
		for _, step := range job.Steps {
			if strings.Contains(step.Run, "git clone") || strings.Contains(step.Run, "Falling back") {
				t.Fatal("floating or fallback host clone remains")
			}
			if step.With["path"] == "cpa-plugin-key-manager" {
				plugin = true
				if step.With["ref"] != "${{ needs.resolve.outputs.plugin_sha }}" {
					t.Fatalf("%s plugin checkout is not pinned", name)
				}
			}
			if step.With["path"] == "CLIProxyAPI" {
				host = true
				if step.With["repository"] != "router-for-me/CLIProxyAPI" || step.With["ref"] != "${{ needs.resolve.outputs.host_sha }}" {
					t.Fatalf("%s host checkout is not pinned", name)
				}
			}
		}
		if !plugin || !host {
			t.Fatalf("%s missing source checkout", name)
		}
	}
	release := workflow.Jobs["release"]
	if release.Permissions["contents"] != "write" {
		t.Fatal("release job requires narrow contents write")
	}
	var publish workflowStep
	for _, step := range release.Steps {
		if strings.HasPrefix(step.Uses, "softprops/action-gh-release@") {
			publish = step
		}
	}
	if publish.With["tag_name"] != "${{ needs.resolve.outputs.tag }}" || publish.With["prerelease"] != "${{ contains(needs.resolve.outputs.tag, '-') }}" {
		t.Fatal("publication must use the resolved tag")
	}
	if publish.With["make_latest"] != "${{ contains(needs.resolve.outputs.tag, '-') && 'false' || 'true' }}" {
		t.Fatal("prerelease must never replace latest stable")
	}
	tests := workflow.Jobs["test"]
	node, vet, frontend := false, false, false
	for _, step := range tests.Steps {
		node = node || (strings.HasPrefix(step.Uses, "actions/setup-node@") && step.With["node-version"] == "24")
		vet = vet || strings.Contains(step.Run, "go vet ./...")
		frontend = frontend || strings.Contains(step.Run, "node --test web/*.test.cjs")
	}
	if !node || !vet || !frontend {
		t.Fatal("release tests must include Node 24, static analysis and frontend regressions")
	}
}

func TestReleaseResolverBindsTagSourceAndRejectsWrongDispatch(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git unavailable")
	}
	bash, err := exec.LookPath("bash")
	if err != nil && runtime.GOOS == "windows" {
		candidate := filepath.Join(filepath.Dir(filepath.Dir(git)), "bin", "bash.exe")
		if _, statErr := os.Stat(candidate); statErr == nil {
			bash = candidate
			err = nil
		}
	}
	if err != nil {
		t.Skip("bash unavailable")
	}
	raw, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]workflowJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	script := ""
	for _, step := range workflow.Jobs["resolve"].Steps {
		if step.Run != "" {
			script = step.Run
		}
	}
	dir := t.TempDir()
	runGit := func(args ...string) string {
		cmd := exec.Command(git, args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	runGit("init", "-q")
	runGit("config", "user.name", "Release Resolver Fixture")
	runGit("config", "user.email", "resolver@example.invalid")
	if err := os.MkdirAll(filepath.Join(dir, "internal", "plugin"), 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "internal", "plugin", "plugin.go")
	if err := os.WriteFile(source, []byte("package plugin\nconst (\n PluginVersion = \"1.2.3\"\n)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runGit("add", ".")
	runGit("commit", "-qm", "tag source")
	tagSHA := runGit("rev-parse", "HEAD")
	runGit("tag", "v1.2.3")
	runGit("tag", "v9.9.9")
	if err := os.WriteFile(source, []byte("package plugin\nconst (\n PluginVersion = \"1.2.4\"\n)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runGit("add", ".")
	runGit("commit", "-qm", "newer branch source")
	for _, tc := range []struct {
		name, input, refType, refName string
		ok                            bool
	}{
		{"tag push", "", "tag", "v1.2.3", true},
		{"manual existing tag", "v1.2.3", "branch", "main", true},
		{"manual needs tag", "", "branch", "main", false},
		{"missing tag", "v1.2.99", "branch", "main", false},
		{"wrong version", "v9.9.9", "branch", "main", false},
		{"script injection rejected", "v1.2.3;touch injected", "branch", "main", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(dir, "output-"+strings.ReplaceAll(tc.name, " ", "-")+".txt")
			// bash on Windows accepts forward slashes for an absolute output path.
			cmd := exec.Command(bash, "-c", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "INPUT_TAG="+tc.input, "GITHUB_REF_TYPE="+tc.refType, "GITHUB_REF_NAME="+tc.refName, "GITHUB_OUTPUT="+filepath.ToSlash(output))
			logs, err := cmd.CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("success=%v want %v: %s", err == nil, tc.ok, logs)
			}
			if tc.ok {
				data, err := os.ReadFile(output)
				if err != nil {
					t.Fatal(err)
				}
				for _, part := range []string{"tag=v1.2.3", "plugin_sha=" + tagSHA, "host_sha=681ce41b6e44c45b15b79378b003909d6ba29e68"} {
					if !strings.Contains(string(data), part) {
						t.Fatalf("wrong immutable output: %s", data)
					}
				}
			}
			if _, err := os.Stat(filepath.Join(dir, "injected")); !os.IsNotExist(err) {
				t.Fatal("input was evaluated as shell code")
			}
		})
	}
}
func TestReleaseArchivesIncludeBackgroundCleanupGuide(t *testing.T) {
	raw, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]workflowJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	var build string
	for _, step := range workflow.Jobs["build"].Steps {
		if strings.Contains(step.Run, "go build -trimpath") {
			build = step.Run
		}
	}
	if strings.Count(build, "CONTENT_INTERCEPT.md") != 3 {
		t.Fatal("content interception guide must be copied and included in zip/tar archives")
	}
	if strings.Count(build, "CLEANUP_JOBS.md") != 3 {
		t.Fatal("cleanup task guide must be copied and included in zip/tar archives")
	}
}
func TestReleaseRecoveryPinsProvenanceAndUsesIntelRunner(t *testing.T) {
	raw, err := os.ReadFile(".github/workflows/release-recovery.yml")
	if err != nil {
		t.Fatal(err)
	}
	var w struct {
		Permissions map[string]string `yaml:"permissions"`
		Jobs        map[string]struct {
			RunsOn string `yaml:"runs-on"`
			workflowJob
		} `yaml:"jobs"`
	}
	// Parse both ordinary workflow jobs and runner labels independently.
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	if w.Permissions["contents"] != "read" || w.Permissions["actions"] != "read" {
		t.Fatal("recovery default permissions must be read-only")
	}
	jobs := tree["jobs"].(map[string]any)
	if jobs["build_intel"].(map[string]any)["runs-on"] != "macos-15-intel" {
		t.Fatal("recovery must use explicit Intel pool")
	}
	// workflowJob's fields are not YAML-inline through embedding; inspect maps.
	validate := jobs["validate"].(map[string]any)
	steps := validate["steps"].([]any)
	source := string(raw)
	for _, guard := range []string{"run.workflow_id !== workflow.id", "run.head_sha !== process.env.PLUGIN_SHA", "run.head_branch !== process.env.RELEASE_TAG", "run.status !== 'completed'", "intel[0].steps.length !== 0", "intel[0].runner_name", "Unit Tests", "artifacts.length !== names.length", "getReleaseByTag", "refs/tags/$TAG^{commit}", "v$VERSION", "681ce41b6e44c45b15b79378b003909d6ba29e68"} {
		if !strings.Contains(source, guard) {
			t.Fatalf("missing recovery guard: %s", guard)
		}
	}
	if len(steps) < 2 {
		t.Fatal("missing provenance validation")
	}
	if strings.Contains(source, "run: ${{") {
		t.Fatal("inputs must not be interpolated into shell")
	}
	build := jobs["build_intel"].(map[string]any)
	buildSteps := build["steps"].([]any)
	pinnedPlugin, pinnedHost := false, false
	for _, entry := range buildSteps {
		step := entry.(map[string]any)
		with, ok := step["with"].(map[string]any)
		if !ok {
			continue
		}
		if with["path"] == "cpa-plugin-key-manager" {
			pinnedPlugin = with["ref"] == "${{ needs.validate.outputs.plugin_sha }}"
		}
		if with["path"] == "CLIProxyAPI" {
			pinnedHost = with["ref"] == "${{ needs.validate.outputs.host_sha }}"
		}
	}
	if !pinnedPlugin || !pinnedHost {
		t.Fatal("recovery build inputs must be immutable")
	}
	publish := jobs["publish"].(map[string]any)
	permissions := publish["permissions"].(map[string]any)
	if permissions["contents"] != "write" {
		t.Fatal("only publish job may write releases")
	}
	for name, entry := range jobs {
		if name == "publish" {
			continue
		}
		if p, ok := entry.(map[string]any)["permissions"].(map[string]any); ok && p["contents"] == "write" {
			t.Fatal("nonpublishing job writes contents")
		}
	}
	for _, guard := range []string{"assert {p.name for p in root.iterdir()}==expected", "Packed binary differs", "Bundled source differs", "make_latest:", "run-id: ${{ needs.validate.outputs.source_run_id }}"} {
		if !strings.Contains(source, guard) {
			t.Fatalf("missing artifact recovery verification: %s", guard)
		}
	}
}
