// Package imagepolicy validates container image references against an
// admin-controlled allowlist of trusted repositories.
//
// TracerConfig.spec.image is copied by the operator into a DaemonSet that runs
// as UID 0 with CAP_SYS_ADMIN, host PID, and host /proc mounted. Without a
// gate, anyone able to write a (cluster-scoped) TracerConfig could point that
// at an arbitrary image and get root on every node. The operator therefore
// resolves spec.image against this allowlist and refuses to create the agent
// when it does not match, defaulting the allowlist to the operator's own
// trusted repository.
package imagepolicy

import (
	"fmt"
	"strings"
)

const (
	dockerDefaultRegistry = "docker.io"
	dockerLegacyRegistry  = "index.docker.io"

	AllowAnyRepository = "*"
)

// NormalizeRepository extracts the registry+repository portion of an image
// reference, stripping any tag and digest and applying Docker Hub's implicit
// normalization. It returns an error for a reference that has no repository.
//
//	ghcr.io/gma1k/podtrace:0.14.3      -> ghcr.io/gma1k/podtrace
//	ghcr.io/gma1k/podtrace@sha256:...  -> ghcr.io/gma1k/podtrace
//	registry:5000/team/app:latest      -> registry:5000/team/app
//	attacker/x                         -> docker.io/attacker/x
//	nginx                              -> docker.io/library/nginx
func NormalizeRepository(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", fmt.Errorf("image reference is empty")
	}

	if at := strings.IndexByte(ref, '@'); at >= 0 {
		ref = ref[:at]
	}

	registry, remainder := splitRegistry(ref)

	if colon := strings.LastIndexByte(remainder, ':'); colon >= 0 {
		remainder = remainder[:colon]
	}

	if remainder == "" {
		return "", fmt.Errorf("image reference %q has no repository path", ref)
	}

	registry = strings.ToLower(registry)
	if registry == dockerLegacyRegistry {
		registry = dockerDefaultRegistry
	}
	if registry == "" || registry == dockerDefaultRegistry {
		registry = dockerDefaultRegistry
		if !strings.Contains(remainder, "/") {
			remainder = "library/" + remainder
		}
	}

	return registry + "/" + remainder, nil
}

func splitRegistry(ref string) (registry, remainder string) {
	slash := strings.IndexByte(ref, '/')
	if slash < 0 {
		return "", ref
	}
	first := ref[:slash]
	if strings.ContainsAny(first, ".:") || first == "localhost" || strings.ToLower(first) != first {
		return first, ref[slash+1:]
	}
	return "", ref
}

// RepoAllowed reports whether ref resolves to a repository under one of
// allowedRepos.
func RepoAllowed(ref string, allowedRepos []string) error {
	for _, allowed := range allowedRepos {
		if strings.TrimSpace(allowed) == AllowAnyRepository {
			return nil
		}
	}

	repo, err := NormalizeRepository(ref)
	if err != nil {
		return fmt.Errorf("spec.image %q is not a valid image reference: %w", ref, err)
	}

	for _, allowed := range allowedRepos {
		norm, err := NormalizeRepository(allowed)
		if err != nil {
			continue
		}
		if repo == norm || strings.HasPrefix(repo, norm+"/") {
			return nil
		}
	}

	return fmt.Errorf(
		"spec.image %q resolves to repository %q, which is not in the operator's allowed set %v; "+
			"the agent runs as root with CAP_SYS_ADMIN on every node, so its image must come from a trusted repository. "+
			"Set an allowed repository via the operator's PODTRACE_ALLOWED_AGENT_IMAGE_REPOS if this image is trusted",
		ref, repo, allowedRepos)
}
