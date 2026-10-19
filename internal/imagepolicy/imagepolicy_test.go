package imagepolicy

import "testing"

func TestNormalizeRepository(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"ghcr.io/gma1k/podtrace:0.14.3", "ghcr.io/gma1k/podtrace"},
		{"ghcr.io/gma1k/podtrace", "ghcr.io/gma1k/podtrace"},
		{"ghcr.io/gma1k/podtrace@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "ghcr.io/gma1k/podtrace"},
		{"ghcr.io/gma1k/podtrace:0.14.3@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "ghcr.io/gma1k/podtrace"},
		{"registry:5000/team/app:latest", "registry:5000/team/app"},
		{"registry:5000/team/app", "registry:5000/team/app"},
		{"localhost/app:dev", "localhost/app"},
		{"localhost:5000/app", "localhost:5000/app"},
		{"attacker/x", "docker.io/attacker/x"},
		{"attacker/x:latest", "docker.io/attacker/x"},
		{"nginx", "docker.io/library/nginx"},
		{"nginx:1.27", "docker.io/library/nginx"},
		{"docker.io/library/nginx", "docker.io/library/nginx"},
		{"  ghcr.io/gma1k/podtrace:tag  ", "ghcr.io/gma1k/podtrace"},
	}
	for _, c := range cases {
		got, err := NormalizeRepository(c.in)
		if err != nil {
			t.Errorf("NormalizeRepository(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeRepository(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeRepository_Errors(t *testing.T) {
	for _, in := range []string{"", "   ", "ghcr.io/", "ghcr.io/@sha256:abc"} {
		if _, err := NormalizeRepository(in); err == nil {
			t.Errorf("NormalizeRepository(%q) expected error, got nil", in)
		}
	}
}

func TestRepoAllowed_EmptyAllowlistFailsClosed(t *testing.T) {
	for _, allowed := range [][]string{nil, {}, {""}, {" "}} {
		if err := RepoAllowed("attacker/evil:latest", allowed); err == nil {
			t.Errorf("allowlist %q must refuse an untrusted image", allowed)
		}
	}
}

func TestRepoAllowed_ExplicitWildcardAllowsEverything(t *testing.T) {
	if err := RepoAllowed("attacker/evil:latest", []string{" * "}); err != nil {
		t.Errorf("explicit wildcard must allow any image, got %v", err)
	}
}

func TestRepoAllowed_RegistryHostIsCaseInsensitive(t *testing.T) {
	cases := []struct {
		ref     string
		allowed string
	}{
		{"GHCR.IO/gma1k/podtrace:0.14.3", "ghcr.io/gma1k/podtrace"},
		{"ghcr.io/gma1k/podtrace:0.14.3", "Ghcr.Io/gma1k/podtrace"},
		{"Registry.Internal:5000/team/app", "registry.internal:5000/team"},
		{"index.docker.io/library/nginx", "nginx"},
		{"docker.io/nginx", "docker.io/library/nginx"},
	}
	for _, c := range cases {
		if err := RepoAllowed(c.ref, []string{c.allowed}); err != nil {
			t.Errorf("RepoAllowed(%q, [%q]) = %v, want allowed", c.ref, c.allowed, err)
		}
	}
}

func TestRepoAllowed_RepositoryPathStaysCaseSensitive(t *testing.T) {
	if err := RepoAllowed("ghcr.io/GMA1K/podtrace:tag", []string{"ghcr.io/gma1k/podtrace"}); err == nil {
		t.Error("a repository path differing in case must not match")
	}
}

func TestRepoAllowed_ExactAndSubRepo(t *testing.T) {
	allowed := []string{"ghcr.io/gma1k/podtrace"}
	for _, ref := range []string{
		"ghcr.io/gma1k/podtrace",
		"ghcr.io/gma1k/podtrace:0.14.3",
		"ghcr.io/gma1k/podtrace@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	} {
		if err := RepoAllowed(ref, allowed); err != nil {
			t.Errorf("RepoAllowed(%q) should be allowed, got %v", ref, err)
		}
	}
}

func TestRepoAllowed_ParentPrefixAdmitsChildren(t *testing.T) {
	allowed := []string{"ghcr.io/gma1k"}
	if err := RepoAllowed("ghcr.io/gma1k/podtrace:tag", allowed); err != nil {
		t.Errorf("child repo under an allowed parent should be allowed, got %v", err)
	}
}

func TestRepoAllowed_RejectsBoundaryLookalike(t *testing.T) {
	allowed := []string{"ghcr.io/gma1k/podtrace"}
	for _, ref := range []string{
		"ghcr.io/gma1k/podtrace-evil:latest",
		"ghcr.io/gma1k-evil/podtrace:latest",
		"attacker/x:latest",
		"nginx",
		"evil.example.com/gma1k/podtrace:latest",
	} {
		if err := RepoAllowed(ref, allowed); err == nil {
			t.Errorf("RepoAllowed(%q) must be rejected against %v", ref, allowed)
		}
	}
}

func TestRepoAllowed_MultipleAllowedRepos(t *testing.T) {
	allowed := []string{"ghcr.io/gma1k/podtrace", "registry.internal:5000/mirror/podtrace"}
	if err := RepoAllowed("registry.internal:5000/mirror/podtrace:0.14.3", allowed); err != nil {
		t.Errorf("mirror repo should be allowed, got %v", err)
	}
	if err := RepoAllowed("registry.internal:5000/other/thing", allowed); err == nil {
		t.Error("non-listed repo on an allowed registry must still be rejected")
	}
}

func TestRepoAllowed_InvalidReferenceRejected(t *testing.T) {
	if err := RepoAllowed("", []string{"ghcr.io/gma1k/podtrace"}); err == nil {
		t.Error("empty image reference must be rejected when a policy is set")
	}
}

func TestRepoAllowed_SkipsMalformedAllowlistEntries(t *testing.T) {
	allowed := []string{"", "  ", "ghcr.io/gma1k/podtrace"}
	if err := RepoAllowed("ghcr.io/gma1k/podtrace:tag", allowed); err != nil {
		t.Errorf("a valid allowlist entry must still match past malformed ones, got %v", err)
	}
	if err := RepoAllowed("attacker/x", []string{"", "  "}); err == nil {
		t.Error("an allowlist of only malformed entries must reject a non-matching image")
	}
}
