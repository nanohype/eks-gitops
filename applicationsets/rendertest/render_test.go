// Package rendertest renders the committed Karpenter EC2NodeClass patch template
// from applicationsets/addons-operations-kustomize.yaml exactly the way the ArgoCD
// ApplicationSet controller does — Go text/template plus sprig, with
// Option("missingkey=error") mirroring the appset's
// goTemplateOptions: ["missingkey=error"] — against fixture ArgoCD cluster-Secret
// label/annotation sets, and asserts the resulting subnetSelectorTerms shape for
// each network mode.
//
// Why it exists: the patch carries if/range control flow inside a `patch: |-`
// string block. The appset schema gate validates that string's YAML shape and the
// kustomize build renders the overlays, but nothing renders the template against
// per-cluster data — so a control-flow edit that breaks the render (a bare index
// that trips missingkey=error, or a dig that panics on the string label map the
// cluster generator hands back) validates clean and only breaks at sync, on every
// cluster the generator produces. This harness closes that gap by driving the real
// committed template against create, adopt, and legacy-no-label fixtures.
package rendertest

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"gopkg.in/yaml.v3"
)

// patchOp is one entry of the rendered JSON6902 patch list.
type patchOp struct {
	Op    string      `yaml:"op"`
	Path  string      `yaml:"path"`
	Value interface{} `yaml:"value"`
}

func TestKarpenterSubnetSelector(t *testing.T) {
	patch := loadEC2NodeClassPatch(t)

	t.Run("create mode keeps the tag selector", func(t *testing.T) {
		labels, annotations := loadClusterMeta(t, "cluster-create.yaml")
		ops := renderOps(t, patch, labels, annotations)
		assertRole(t, ops, "alpha-karpenter-node")
		assertTagSelector(t, subnetTerms(t, ops), "alpha")
	})

	t.Run("adopt mode selects private subnets by id", func(t *testing.T) {
		labels, annotations := loadClusterMeta(t, "cluster-adopt.yaml")
		ops := renderOps(t, patch, labels, annotations)
		assertRole(t, ops, "bravo-karpenter-node")
		assertIDSelector(t, subnetTerms(t, ops),
			[]string{"subnet-priv-a", "subnet-priv-b", "subnet-priv-c"})
	})

	// A cluster Secret written before the network_mode label existed must still
	// render — as create — instead of tripping missingkey=error and breaking the
	// whole ApplicationSet render fleet-wide.
	t.Run("legacy secret with no network_mode label renders as create", func(t *testing.T) {
		labels, annotations := loadClusterMeta(t, "cluster-nolabel.yaml")
		ops := renderOps(t, patch, labels, annotations)
		assertRole(t, ops, "charlie-karpenter-node")
		assertTagSelector(t, subnetTerms(t, ops), "charlie")
	})
}

// loadEC2NodeClassPatch reads the committed appset and returns the EC2NodeClass
// kustomize patch template verbatim — the exact string ArgoCD would render.
func loadEC2NodeClassPatch(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "addons-operations-kustomize.yaml"))
	if err != nil {
		t.Fatalf("read appset: %v", err)
	}
	var doc struct {
		Spec struct {
			Template struct {
				Spec struct {
					Source struct {
						Kustomize struct {
							Patches []struct {
								Target struct {
									Kind string `yaml:"kind"`
								} `yaml:"target"`
								Patch string `yaml:"patch"`
							} `yaml:"patches"`
						} `yaml:"kustomize"`
					} `yaml:"source"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse appset: %v", err)
	}
	for _, p := range doc.Spec.Template.Spec.Source.Kustomize.Patches {
		if p.Target.Kind == "EC2NodeClass" {
			if p.Patch == "" {
				t.Fatal("EC2NodeClass patch template is empty")
			}
			return p.Patch
		}
	}
	t.Fatal("no EC2NodeClass patch found in addons-operations-kustomize.yaml")
	return ""
}

// loadClusterMeta reads a fixture cluster Secret and returns its labels and
// annotations, the two maps the patch template reads.
func loadClusterMeta(t *testing.T, name string) (labels, annotations map[string]string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var secret struct {
		Metadata struct {
			Labels      map[string]string `yaml:"labels"`
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(raw, &secret); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return secret.Metadata.Labels, secret.Metadata.Annotations
}

// renderOps renders the patch template the way ArgoCD does and returns the parsed
// ops, failing if the render errors, produces invalid YAML, or drifts from the
// three-op role/subnet/securityGroup shape.
func renderOps(t *testing.T, patch string, labels, annotations map[string]string) []patchOp {
	t.Helper()
	tmpl, err := template.New("patch").
		Funcs(sprig.TxtFuncMap()).
		Option("missingkey=error").
		Parse(patch)
	if err != nil {
		t.Fatalf("parse patch template: %v", err)
	}
	// Mirror the ArgoCD cluster generator: metadata.labels and metadata.annotations
	// arrive as string maps, the exact shape that made a dig-based read panic in
	// this template's history — so the harness reproduces it rather than passing
	// the more forgiving map[string]interface{}.
	data := map[string]interface{}{
		"metadata": map[string]interface{}{
			"labels":      labels,
			"annotations": annotations,
		},
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("render patch template: %v", err)
	}
	var ops []patchOp
	if err := yaml.Unmarshal(buf.Bytes(), &ops); err != nil {
		t.Fatalf("rendered patch is not valid YAML: %v\n--- rendered ---\n%s", err, buf.String())
	}
	wantPaths := []string{"/spec/role", "/spec/subnetSelectorTerms", "/spec/securityGroupSelectorTerms"}
	if len(ops) != len(wantPaths) {
		t.Fatalf("expected %d patch ops, got %d\n%s", len(wantPaths), len(ops), buf.String())
	}
	for i, want := range wantPaths {
		if ops[i].Op != "replace" || ops[i].Path != want {
			t.Fatalf("op %d = %q %q, want replace %q\n%s", i, ops[i].Op, ops[i].Path, want, buf.String())
		}
	}
	return ops
}

func subnetTerms(t *testing.T, ops []patchOp) []interface{} {
	t.Helper()
	for _, op := range ops {
		if op.Path != "/spec/subnetSelectorTerms" {
			continue
		}
		terms, ok := op.Value.([]interface{})
		if !ok {
			t.Fatalf("subnetSelectorTerms value is %T, want a list", op.Value)
		}
		if len(terms) == 0 {
			t.Fatal("subnetSelectorTerms rendered empty")
		}
		return terms
	}
	t.Fatal("no /spec/subnetSelectorTerms op in rendered patch")
	return nil
}

func assertRole(t *testing.T, ops []patchOp, want string) {
	t.Helper()
	for _, op := range ops {
		if op.Path == "/spec/role" {
			if got, _ := op.Value.(string); got != want {
				t.Fatalf("role = %q, want %q", got, want)
			}
			return
		}
	}
	t.Fatal("no /spec/role op in rendered patch")
}

// assertTagSelector checks the create-mode shape: one term selecting by the
// internal-elb role tag plus this cluster's ownership tag, and never by id.
func assertTagSelector(t *testing.T, terms []interface{}, cluster string) {
	t.Helper()
	if len(terms) != 1 {
		t.Fatalf("tag selector should have exactly 1 term, got %d: %#v", len(terms), terms)
	}
	term, ok := terms[0].(map[string]interface{})
	if !ok {
		t.Fatalf("term is %T, want a map", terms[0])
	}
	if _, hasID := term["id"]; hasID {
		t.Fatalf("create-mode term must not select by id: %#v", term)
	}
	tags, ok := term["tags"].(map[string]interface{})
	if !ok {
		t.Fatalf("term carries no tags map: %#v", term)
	}
	if got := tags["kubernetes.io/role/internal-elb"]; got != "1" {
		t.Fatalf("internal-elb tag = %v (%T), want \"1\"", got, got)
	}
	clusterKey := "kubernetes.io/cluster/" + cluster
	if got := tags[clusterKey]; got != "shared" {
		t.Fatalf("%s = %v, want \"shared\"", clusterKey, got)
	}
}

// assertIDSelector checks the adopt-mode shape: one `- id:` term per fixture
// subnet id, in order, and never a tag term.
func assertIDSelector(t *testing.T, terms []interface{}, wantIDs []string) {
	t.Helper()
	if len(terms) != len(wantIDs) {
		t.Fatalf("id selector should have %d terms, got %d: %#v", len(wantIDs), len(terms), terms)
	}
	for i, raw := range terms {
		term, ok := raw.(map[string]interface{})
		if !ok {
			t.Fatalf("term %d is %T, want a map", i, raw)
		}
		if _, hasTags := term["tags"]; hasTags {
			t.Fatalf("adopt-mode term %d must not select by tag: %#v", i, term)
		}
		if got, _ := term["id"].(string); got != wantIDs[i] {
			t.Fatalf("term %d id = %q, want %q", i, got, wantIDs[i])
		}
	}
}
