package rendertest

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoArchivedYAMLModuleIsLinked keeps the harness on go.yaml.in/yaml/v3, the
// YAML organization's maintained continuation of the archived gopkg.in/yaml.v3.
//
// Renovate cannot hold that move. Its gomod manager does not apply replacement
// updates: renovate 44.239.1 logs "gomod manager does not support replacement
// updates yet" and changes nothing. So the module's own build graph is read
// instead, and no package this module compiles, its tests included, may come
// from the archived gopkg.in/yaml path, whether imported here or pulled in by a
// dependency.
func TestNoArchivedYAMLModuleIsLinked(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-test", "./...").Output()
	if err != nil {
		t.Fatalf("go list -deps -test ./...: %v", err)
	}
	pkgs := strings.Fields(string(out))
	if len(pkgs) == 0 {
		t.Fatal("go list -deps -test ./... listed no packages, so nothing was checked")
	}
	for _, pkg := range pkgs {
		if strings.HasPrefix(pkg, "gopkg.in/yaml.") {
			t.Errorf("%s is linked; parse YAML with go.yaml.in/yaml/v3", pkg)
		}
	}
}
