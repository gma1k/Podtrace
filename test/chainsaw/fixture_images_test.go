package chainsaw

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

const workflowFile = "../../.github/workflows/chainsaw.yml"

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	root, err := os.OpenRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	raw, err := root.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func readWorkflow(t *testing.T) []byte {
	t.Helper()
	root, err := os.OpenRoot("../..")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	raw, err := root.ReadFile(".github/workflows/chainsaw.yml")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var imageLine = regexp.MustCompile(`(?m)^\s*-?\s*image:\s*"?([^"\s]+)"?\s*$`)

func preloadedUpstreamImages(t *testing.T) []string {
	t.Helper()
	raw := readWorkflow(t)
	var workflow struct {
		Env map[string]string `json:"env"`
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("parse %s: %v", workflowFile, err)
	}
	images := strings.Fields(workflow.Env["UPSTREAM_FIXTURE_IMAGES"])
	if len(images) == 0 {
		t.Fatalf("%s has no UPSTREAM_FIXTURE_IMAGES", workflowFile)
	}
	return images
}

func fixtureImages(t *testing.T) map[string][]string {
	t.Helper()
	used := map[string][]string{}
	err := filepath.WalkDir(testsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		raw := readTestFile(t, path)
		for _, m := range imageLine.FindAllStringSubmatch(string(raw), -1) {
			image := m[1]
			if strings.Contains(image, "$") || strings.HasSuffix(image, ":ci") || strings.HasPrefix(image, "ghcr.io/gma1k/") {
				continue
			}
			used[image] = append(used[image], path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return used
}

func TestEveryPublicFixtureImageIsPreloaded(t *testing.T) {
	preloaded := preloadedUpstreamImages(t)
	for image, files := range fixtureImages(t) {
		if !slices.Contains(preloaded, image) {
			t.Errorf("%s (used by %v) is not in UPSTREAM_FIXTURE_IMAGES in %s, so every kind node "+
				"pulls it from the registry with no retry", image, files, workflowFile)
		}
	}
}

func TestFixtureImagesAreNotFloating(t *testing.T) {
	for image, files := range fixtureImages(t) {
		if !strings.Contains(image, ":") || strings.HasSuffix(image, ":latest") {
			t.Errorf("%s (used by %v) floats: a new upstream push changes the test without a commit", image, files)
		}
	}
}

func TestEveryLocallyBuiltFixtureImageIsBuiltAndLoadedInCI(t *testing.T) {
	workflow := string(readWorkflow(t))
	err := filepath.WalkDir(testsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		body := readTestFile(t, path)
		for _, m := range imageLine.FindAllStringSubmatch(string(body), -1) {
			image := m[1]
			if !strings.HasPrefix(image, "podtrace-") || !strings.HasSuffix(image, ":ci") {
				continue
			}
			if !strings.Contains(workflow, "-t "+image+" ") {
				t.Errorf("%s (used by %s) is never built by %s; the Deployment waits on an image "+
					"no node has and the test fails only in CI", image, path, workflowFile)
			}
			if !strings.Contains(workflow, "            "+image+" \\") {
				t.Errorf("%s (used by %s) is built but not loaded into the kind nodes by %s", image, path, workflowFile)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
