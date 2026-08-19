package rendertest

import (
	"os"
	"path/filepath"
	"testing"
)

// The render tests fail when testdata is missing, but they fail because os.Open
// errors on an absent path — a property of the standard library's error
// handling, not of this suite. A fixture removed alongside the test that reads
// it leaves nothing behind to notice.
//
// These fixtures encode the cases the appset templates must handle: a cluster
// that creates its own VPC, one that adopts a shared VPC, one with no
// network_mode label at all, and the with/without-bucket pairs that decide
// whether an artifact store is configured. Losing one silently narrows what the
// render gate covers to whatever remains.
var required = []string{
	"cluster-create.yaml",
	"cluster-adopt.yaml",
	"cluster-nolabel.yaml",
	"argo-workflows-cluster-with-bucket.yaml",
	"argo-workflows-cluster-no-bucket.yaml",
	"observability-cluster-with-buckets.yaml",
	"observability-cluster-no-buckets.yaml",
}

func TestFixtureCorpusIsIntact(t *testing.T) {
	for _, name := range required {
		path := filepath.Join("testdata", name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("required fixture %s is absent: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("required fixture %s is empty — it loads without error and "+
				"asserts nothing", name)
		}
	}

	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	var found int
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".yaml" {
			found++
		}
	}
	if found < len(required) {
		t.Fatalf("testdata holds %d yaml fixtures, fewer than the %d this suite "+
			"requires — discovery is matching a smaller corpus than the tests assume",
			found, len(required))
	}
	t.Logf("fixture corpus intact: %d required present, %d yaml files in testdata",
		len(required), found)
}
