// This file renders the committed templatePatch from
// applicationsets/addons-ai-platform.yaml against every list element, the way
// the ArgoCD ApplicationSet controller does — Go text/template plus sprig, with
// Option("missingkey=error") mirroring the appset's goTemplateOptions — and
// asserts what each generated Application's automated prune becomes.
//
// Why it exists: the patch is a string, so the appset-schema gate sees only that
// it is a string. It decides whether an Application may delete what it stops
// rendering, and it is the lever that turns one Application's prune off while
// something it installs moves to another owner (envoy-gateway ran with it off
// while Envoy Gateway's CRDs moved to envoy-gateway-crds). Every committed
// element runs autoPrune: true today, so the false arm is rendered against a
// synthetic element below; a lever proven only in the direction nobody is
// pulling it would be found broken on the day it is needed. An element that
// drops its autoPrune field, spells it as a string, or a patch that renders
// anything but spec.syncPolicy.automated.prune would otherwise validate clean and
// surface only at sync — as an ApplicationSet that generates nothing, or as a
// prune nobody meant to enable.
package rendertest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"go.yaml.in/yaml/v3"
)

func TestAIPlatformPrunePatch(t *testing.T) {
	patch, elements := loadAIPlatformPatch(t)
	if len(elements) == 0 {
		t.Fatal("addons-ai-platform.yaml lists no elements — nothing to render the patch against")
	}
	labels, annotations := loadClusterMeta(t, "cluster-create.yaml")

	for _, el := range elements {
		name, _ := el["appName"].(string)
		t.Run(name, func(t *testing.T) {
			want, ok := el["autoPrune"].(bool)
			if !ok {
				t.Fatalf("element %q: autoPrune must be a YAML boolean, got %#v", name, el["autoPrune"])
			}
			got := renderPrune(t, patch, el, labels, annotations)
			if got != want {
				t.Fatalf("element %q: rendered prune = %v, autoPrune = %v", name, got, want)
			}
		})
	}

	// Both arms, whatever the committed elements happen to carry: the patch must
	// turn prune off for an element that asks, not only leave it on.
	for _, want := range []bool{true, false} {
		t.Run(fmt.Sprintf("a synthetic element with autoPrune: %v", want), func(t *testing.T) {
			el := map[string]interface{}{"appName": "synthetic", "autoPrune": want}
			if got := renderPrune(t, patch, el, labels, annotations); got != want {
				t.Fatalf("rendered prune = %v, autoPrune = %v", got, want)
			}
		})
	}

	// missingkey=error is what makes autoPrune mandatory. An element without it
	// must fail the render, not inherit a value.
	t.Run("an element without autoPrune fails the render", func(t *testing.T) {
		el := map[string]interface{}{"appName": "no-prune-field"}
		if _, err := execute(patch, el, labels, annotations); err == nil {
			t.Fatal("patch rendered for an element with no autoPrune — missingkey=error is not in force")
		}
	})
}

// renderPrune renders the patch for one element and returns the prune value,
// failing if the patch sets anything other than spec.syncPolicy.automated.prune.
func renderPrune(t *testing.T, patch string, el map[string]interface{}, labels, annotations map[string]string) bool {
	t.Helper()
	out, err := execute(patch, el, labels, annotations)
	if err != nil {
		t.Fatalf("render templatePatch: %v", err)
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("rendered patch is not valid YAML: %v\n%s", err, out)
	}
	path := []string{"spec", "syncPolicy", "automated"}
	node := doc
	for _, key := range path {
		if len(node) != 1 {
			t.Fatalf("patch must set only spec.syncPolicy.automated.prune; at %q found keys %v\n%s", key, keys(node), out)
		}
		next, ok := node[key].(map[string]interface{})
		if !ok {
			t.Fatalf("patch has no %q map on the path to prune\n%s", key, out)
		}
		node = next
	}
	if len(node) != 1 {
		t.Fatalf("patch must set only automated.prune; found keys %v\n%s", keys(node), out)
	}
	prune, ok := node["prune"].(bool)
	if !ok {
		t.Fatalf("automated.prune rendered as %#v, not a boolean\n%s", node["prune"], out)
	}
	return prune
}

func execute(patch string, el map[string]interface{}, labels, annotations map[string]string) (string, error) {
	tmpl, err := template.New("patch").
		Funcs(sprig.TxtFuncMap()).
		Option("missingkey=error").
		Parse(patch)
	if err != nil {
		return "", err
	}
	// Mirror the matrix generator: the cluster generator's metadata beside the
	// list element's own keys, in one parameter map.
	data := map[string]interface{}{
		"metadata": map[string]interface{}{
			"labels":      labels,
			"annotations": annotations,
		},
	}
	for k, v := range el {
		data[k] = v
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func keys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// loadAIPlatformPatch reads the committed appset and returns its templatePatch
// verbatim plus the list generator's elements.
func loadAIPlatformPatch(t *testing.T) (string, []map[string]interface{}) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "addons-ai-platform.yaml"))
	if err != nil {
		t.Fatalf("read appset: %v", err)
	}
	var doc struct {
		Spec struct {
			TemplatePatch string `yaml:"templatePatch"`
			Generators    []struct {
				Matrix struct {
					Generators []struct {
						List struct {
							Elements []map[string]interface{} `yaml:"elements"`
						} `yaml:"list"`
					} `yaml:"generators"`
				} `yaml:"matrix"`
			} `yaml:"generators"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse appset: %v", err)
	}
	if doc.Spec.TemplatePatch == "" {
		t.Fatal("addons-ai-platform.yaml carries no templatePatch")
	}
	var elements []map[string]interface{}
	for _, g := range doc.Spec.Generators {
		for _, sub := range g.Matrix.Generators {
			elements = append(elements, sub.List.Elements...)
		}
	}
	return doc.Spec.TemplatePatch, elements
}
