package runner

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/hadrian/pkg/templates"
)

func ct(id, path string) *templates.CompiledTemplate {
	return &templates.CompiledTemplate{
		Template: &templates.Template{ID: id},
		FilePath: path,
	}
}

// TestWarnDuplicateTemplateIDs covers the contract of the shared loader guard:
// warn once per id declared by more than one file, name both paths, stay silent
// when ids are unique, and skip nil / empty-id entries. The duplicate path is
// the only thing standing between a misconfigured template set and a silently
// hidden second finding (duplicate ids collapse to one SARIF rule + fingerprint),
// so the warning content is asserted, not merely its presence.
func TestWarnDuplicateTemplateIDs(t *testing.T) {
	t.Run("duplicate id warns once and names both paths", func(t *testing.T) {
		out := captureStderr(func() {
			warnDuplicateTemplateIDs([]*templates.CompiledTemplate{
				ct("01-api1-bola-read", "templates/rest/a.yaml"),
				ct("01-api1-bola-read", "templates/rest/b.yaml"),
			})
		})
		assert.Equal(t, 1, strings.Count(out, "Duplicate template id"), "expected exactly one warning")
		assert.Contains(t, out, "01-api1-bola-read")
		assert.Contains(t, out, "templates/rest/a.yaml")
		assert.Contains(t, out, "templates/rest/b.yaml")
	})

	t.Run("all distinct ids warn nothing", func(t *testing.T) {
		out := captureStderr(func() {
			warnDuplicateTemplateIDs([]*templates.CompiledTemplate{
				ct("a", "templates/rest/a.yaml"),
				ct("b", "templates/rest/b.yaml"),
			})
		})
		assert.NotContains(t, out, "Duplicate template id")
	})

	t.Run("nil, nil-embedded-Template, and empty-id entries are skipped without warning or panic", func(t *testing.T) {
		out := captureStderr(func() {
			warnDuplicateTemplateIDs([]*templates.CompiledTemplate{
				nil,
				{FilePath: "templates/rest/no-template.yaml"}, // nil embedded *Template
				ct("", "templates/rest/empty1.yaml"),
				ct("", "templates/rest/empty2.yaml"),
			})
		})
		assert.NotContains(t, out, "Duplicate template id",
			"empty IDs must not be treated as duplicates of each other")
	})

	t.Run("three files with same id warn on each collision after the first", func(t *testing.T) {
		out := captureStderr(func() {
			warnDuplicateTemplateIDs([]*templates.CompiledTemplate{
				ct("dup", "templates/rest/a.yaml"),
				ct("dup", "templates/rest/b.yaml"),
				ct("dup", "templates/rest/c.yaml"),
			})
		})
		assert.Equal(t, 2, strings.Count(out, "Duplicate template id"),
			"second and third file each warn against the first-seen path")
	})
}
