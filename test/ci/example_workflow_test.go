package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleSARIFUploadWorkflow(t *testing.T) {
	root := moduleRoot(t)
	workflows := filepath.Join(root, ".github", "workflows")

	err := filepath.WalkDir(workflows, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Errorf("read %s: %v", path, readErr)
			return nil
		}
		if strings.Contains(string(body), "Hadrian Security Scan") {
			t.Errorf("%s contains workflow name %q", path, "Hadrian Security Scan")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", workflows, err)
	}

	example := filepath.Join(root, "docs", "examples", "example-sarif-upload.yml")
	body, err := os.ReadFile(example)
	if err != nil {
		t.Fatalf("example workflow missing at %s: %v", example, err)
	}
	text := string(body)
	if !pinsHadrianVersion(text, "v1.0.0") {
		t.Errorf("%s must pin HADRIAN_VERSION to v1.0.0", example)
	}
	if !showsGoInstallAtVersion(text, "v1.0.0") {
		t.Errorf("%s must go install github.com/praetorian-inc/hadrian/cmd/hadrian at v1.0.0", example)
	}
	if !pinsTemplateCheckoutRef(text) {
		t.Errorf("%s must pin the template checkout ref to HADRIAN_VERSION", example)
	}
	if !showsUploadSARIF(text) {
		t.Errorf("%s must show github/codeql-action/upload-sarif@v3", example)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("module root not found")
		}
		dir = parent
	}
}

func pinsHadrianVersion(text, version string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != "HADRIAN_VERSION" {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		if i := strings.IndexAny(value, " \t#"); i >= 0 {
			value = strings.TrimSpace(value[:i])
			value = strings.Trim(value, `"'`)
		}
		return value == version
	}
	return false
}

func showsGoInstallAtVersion(text, version string) bool {
	const modulePath = "github.com/praetorian-inc/hadrian/cmd/hadrian"
	if !strings.Contains(text, "go install") {
		return false
	}
	return strings.Contains(text, modulePath+"@"+version) ||
		strings.Contains(text, modulePath+"@${HADRIAN_VERSION}") ||
		strings.Contains(text, modulePath+"@${{ env.HADRIAN_VERSION }}")
}

func pinsTemplateCheckoutRef(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "ref:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "ref:"))
		if strings.Contains(value, "HADRIAN_VERSION") {
			return true
		}
	}
	return false
}

func showsUploadSARIF(text string) bool {
	const action = "github/codeql-action/upload-sarif@v3"
	i := strings.Index(text, action)
	if i < 0 {
		return false
	}
	end := i + len(action)
	if end < len(text) {
		c := text[end]
		if c == '.' || (c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
