// This file renders the committed inline helm.values template from
// applicationsets/addons-argo-workflows.yaml exactly the way the ArgoCD
// ApplicationSet controller does — Go text/template plus sprig, with
// Option("missingkey=error") mirroring the appset's
// goTemplateOptions: ["missingkey=error"] — against fixture ArgoCD cluster-Secret
// label/annotation sets, and asserts the S3 artifact repository is injected only
// when the argo-workflows/artifact-bucket annotation is present.
//
// Why it exists: the artifact bucket is per cluster and account-specific, so it
// crosses the seam as the argo-workflows/artifact-bucket cluster-Secret
// annotation that cluster-bootstrap stamps only where the bucket is enabled. The
// appset injects it through an inline `helm.values` string carrying an if-guard,
// so the clusters without the annotation get no (empty-bucket) default artifact
// repository. The helm-render gate templates the chart against the committed
// base + per-env values only — it never renders this per-cluster injection — and
// the appset-schema gate validates the string's YAML shape but not its render, so
// a broken guard (a bare index that trips missingkey=error, an empty bucket
// leaking onto the no-annotation clusters, or a wrong values key) validates clean
// and only surfaces at sync. This harness drives the real committed template
// against with-bucket and no-bucket fixtures.
package rendertest

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"gopkg.in/yaml.v3"
)

func TestArgoWorkflowsArtifactRepo(t *testing.T) {
	tmplStr := loadArgoWorkflowsValues(t)

	t.Run("cluster with the artifact-bucket annotation injects the S3 repo", func(t *testing.T) {
		labels, annotations := loadClusterMeta(t, "argo-workflows-cluster-with-bucket.yaml")
		out := renderValues(t, tmplStr, labels, annotations)

		var v struct {
			UseStaticCredentials *bool `yaml:"useStaticCredentials"`
			ArtifactRepository   struct {
				S3 struct {
					Bucket      string `yaml:"bucket"`
					Region      string `yaml:"region"`
					UseSDKCreds *bool  `yaml:"useSDKCreds"`
				} `yaml:"s3"`
			} `yaml:"artifactRepository"`
		}
		if err := yaml.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("rendered values is not valid YAML: %v\n--- rendered ---\n%s", err, out)
		}
		if want := annotations["argo-workflows/artifact-bucket"]; v.ArtifactRepository.S3.Bucket != want {
			t.Fatalf("s3.bucket = %q, want %q\n%s", v.ArtifactRepository.S3.Bucket, want, out)
		}
		if want := labels["region"]; v.ArtifactRepository.S3.Region != want {
			t.Fatalf("s3.region = %q, want %q\n%s", v.ArtifactRepository.S3.Region, want, out)
		}
		if v.ArtifactRepository.S3.UseSDKCreds == nil || !*v.ArtifactRepository.S3.UseSDKCreds {
			t.Fatalf("s3.useSDKCreds must be true (Pod Identity, no static keys)\n%s", out)
		}
		if v.UseStaticCredentials == nil || *v.UseStaticCredentials {
			t.Fatalf("useStaticCredentials must be false (Pod Identity, no static keys)\n%s", out)
		}
	})

	// A cluster where the bucket is not enabled carries no annotation. The guard
	// must skip the whole block — never render an empty-bucket artifact repo and
	// never trip missingkey=error — so Argo Workflows still deploys, just with no
	// default artifact store.
	t.Run("cluster without the annotation injects no artifact repository", func(t *testing.T) {
		labels, annotations := loadClusterMeta(t, "argo-workflows-cluster-no-bucket.yaml")
		out := renderValues(t, tmplStr, labels, annotations)

		if strings.TrimSpace(out) != "" {
			t.Fatalf("no-annotation cluster must inject empty values (no artifact repo), got:\n%s", out)
		}
		var parsed map[string]interface{}
		if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("rendered values is not valid YAML: %v\n%s", err, out)
		}
		if _, ok := parsed["artifactRepository"]; ok {
			t.Fatalf("no-annotation cluster must not carry artifactRepository:\n%s", out)
		}
	})
}

// loadArgoWorkflowsValues reads the committed appset and returns the argo-workflows
// source's inline helm.values template verbatim — the exact string ArgoCD renders.
func loadArgoWorkflowsValues(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "addons-argo-workflows.yaml"))
	if err != nil {
		t.Fatalf("read appset: %v", err)
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
		t.Fatalf("parse appset: %v", err)
	}
	for _, s := range doc.Spec.Template.Spec.Sources {
		if s.Chart == "argo-workflows" {
			if s.Helm.Values == "" {
				t.Fatal("argo-workflows source carries no inline helm.values template")
			}
			return s.Helm.Values
		}
	}
	t.Fatal("no argo-workflows chart source found in addons-argo-workflows.yaml")
	return ""
}

// renderValues renders the inline values template the way ArgoCD does and returns
// the rendered string, failing on a template parse or execute error.
func renderValues(t *testing.T, tmplStr string, labels, annotations map[string]string) string {
	t.Helper()
	tmpl, err := template.New("values").
		Funcs(sprig.TxtFuncMap()).
		Option("missingkey=error").
		Parse(tmplStr)
	if err != nil {
		t.Fatalf("parse values template: %v", err)
	}
	// Mirror the ArgoCD cluster generator: metadata.labels and metadata.annotations
	// arrive as string maps.
	data := map[string]interface{}{
		"metadata": map[string]interface{}{
			"labels":      labels,
			"annotations": annotations,
		},
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("render values template: %v", err)
	}
	return buf.String()
}
