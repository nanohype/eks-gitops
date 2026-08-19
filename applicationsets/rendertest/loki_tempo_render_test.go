// Renders the committed inline helm.values templates from applicationsets/
// addons-loki.yaml and addons-tempo.yaml exactly the way the ArgoCD ApplicationSet
// controller does, and asserts the S3 storage backend is injected only when the
// observability/loki-bucket (or tempo-bucket) annotation is present.
//
// Why it exists: the log/trace bucket is per cluster and account-specific, so it
// crosses the seam as the observability/loki-bucket and observability/tempo-bucket
// cluster-Secret annotations cluster-bootstrap stamps only on managed-monitoring
// clusters. Each appset injects it through an inline helm.values string carrying an
// if-guard, so a cluster without the annotation keeps the base values'
// filesystem/local storage rather than getting an empty-bucket S3 config. The
// helm-render gate templates the charts against the base + per-env values only — it
// never renders this per-cluster injection — and the appset-schema gate validates
// the string's YAML shape but not its render, so a broken guard (a bare index that
// trips missingkey=error, an empty bucket leaking onto no-annotation clusters, or a
// wrong values key) validates clean and only surfaces at sync. This harness drives
// the real committed templates against with-bucket and no-bucket fixtures.
package rendertest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLokiS3Storage(t *testing.T) {
	tmplStr := loadInlineValues(t, "addons-loki.yaml", "loki")

	t.Run("cluster with the loki-bucket annotation injects S3 storage", func(t *testing.T) {
		labels, annotations := loadClusterMeta(t, "observability-cluster-with-buckets.yaml")
		out := renderValues(t, tmplStr, labels, annotations)

		var v struct {
			Loki struct {
				Storage struct {
					Type        string `yaml:"type"`
					BucketNames struct {
						Chunks string `yaml:"chunks"`
					} `yaml:"bucketNames"`
					S3 struct {
						Region string `yaml:"region"`
					} `yaml:"s3"`
				} `yaml:"storage"`
			} `yaml:"loki"`
		}
		if err := yaml.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("rendered values is not valid YAML: %v\n--- rendered ---\n%s", err, out)
		}
		if v.Loki.Storage.Type != "s3" {
			t.Fatalf("loki.storage.type = %q, want s3\n%s", v.Loki.Storage.Type, out)
		}
		if want := annotations["observability/loki-bucket"]; v.Loki.Storage.BucketNames.Chunks != want {
			t.Fatalf("loki.storage.bucketNames.chunks = %q, want %q\n%s", v.Loki.Storage.BucketNames.Chunks, want, out)
		}
		if want := labels["region"]; v.Loki.Storage.S3.Region != want {
			t.Fatalf("loki.storage.s3.region = %q, want %q\n%s", v.Loki.Storage.S3.Region, want, out)
		}
	})

	t.Run("cluster without the annotation keeps filesystem storage", func(t *testing.T) {
		labels, annotations := loadClusterMeta(t, "observability-cluster-no-buckets.yaml")
		out := renderValues(t, tmplStr, labels, annotations)
		if strings.TrimSpace(out) != "" {
			t.Fatalf("no-annotation cluster must inject no loki S3 override (base filesystem stands), got:\n%s", out)
		}
	})
}

func TestTempoS3Storage(t *testing.T) {
	tmplStr := loadInlineValues(t, "addons-tempo.yaml", "tempo")

	t.Run("cluster with the tempo-bucket annotation injects S3 storage", func(t *testing.T) {
		labels, annotations := loadClusterMeta(t, "observability-cluster-with-buckets.yaml")
		out := renderValues(t, tmplStr, labels, annotations)

		var v struct {
			Tempo struct {
				Storage struct {
					Trace struct {
						Backend string `yaml:"backend"`
						S3      struct {
							Bucket   string `yaml:"bucket"`
							Region   string `yaml:"region"`
							Endpoint string `yaml:"endpoint"`
						} `yaml:"s3"`
					} `yaml:"trace"`
				} `yaml:"storage"`
			} `yaml:"tempo"`
		}
		if err := yaml.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("rendered values is not valid YAML: %v\n--- rendered ---\n%s", err, out)
		}
		if v.Tempo.Storage.Trace.Backend != "s3" {
			t.Fatalf("tempo.storage.trace.backend = %q, want s3\n%s", v.Tempo.Storage.Trace.Backend, out)
		}
		if want := annotations["observability/tempo-bucket"]; v.Tempo.Storage.Trace.S3.Bucket != want {
			t.Fatalf("tempo.storage.trace.s3.bucket = %q, want %q\n%s", v.Tempo.Storage.Trace.S3.Bucket, want, out)
		}
		if want := labels["region"]; v.Tempo.Storage.Trace.S3.Region != want {
			t.Fatalf("tempo.storage.trace.s3.region = %q, want %q\n%s", v.Tempo.Storage.Trace.S3.Region, want, out)
		}
		// Deliberately not symmetric with loki's assertion.
		//
		// Tempo reaches S3 through the minio-go client, which validates the endpoint before
		// it looks at anything else and refuses an empty one:
		//
		//   failed to create minio client: Endpoint:  does not follow ip address or
		//   domain name standards.
		//
		// Tempo then exits at startup, the StatefulSet crashloops, and the Application sits
		// Progressing forever — on a fresh install that is the single thing that holds up
		// catalog convergence, for thirty minutes, until the installer gives up. A bucket
		// A bucket and a region render correctly regardless, which is why asserting those
		// is not enough: the manifest is well-formed and the config incomplete.
		//
		// loki needs no endpoint because its AWS client derives one from the region. The two
		// blocks are asymmetric on purpose.
		if want := "s3." + labels["region"] + ".amazonaws.com"; v.Tempo.Storage.Trace.S3.Endpoint != want {
			t.Fatalf("tempo.storage.trace.s3.endpoint = %q, want %q — tempo's minio client "+
				"rejects an empty endpoint and the pod crashloops\n%s",
				v.Tempo.Storage.Trace.S3.Endpoint, want, out)
		}
	})

	t.Run("cluster without the annotation keeps the local backend", func(t *testing.T) {
		labels, annotations := loadClusterMeta(t, "observability-cluster-no-buckets.yaml")
		out := renderValues(t, tmplStr, labels, annotations)
		if strings.TrimSpace(out) != "" {
			t.Fatalf("no-annotation cluster must inject no tempo S3 override (base local backend stands), got:\n%s", out)
		}
	})
}

// loadInlineValues reads the committed appset and returns the named chart source's
// inline helm.values template verbatim — the exact string ArgoCD renders.
func loadInlineValues(t *testing.T, appsetFile, chart string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", appsetFile))
	if err != nil {
		t.Fatalf("read appset %s: %v", appsetFile, err)
	}
	var doc struct {
		Spec struct {
			Template struct {
				Spec struct {
					Sources []struct {
						Chart string `yaml:"chart"`
						Helm  struct {
							Values string `yaml:"values"`
						} `yaml:"helm"`
					} `yaml:"sources"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse appset %s: %v", appsetFile, err)
	}
	for _, s := range doc.Spec.Template.Spec.Sources {
		if s.Chart == chart {
			if s.Helm.Values == "" {
				t.Fatalf("%s source carries no inline helm.values template", chart)
			}
			return s.Helm.Values
		}
	}
	t.Fatalf("no %s chart source found in %s", chart, appsetFile)
	return ""
}
