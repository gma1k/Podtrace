package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apiextensionsv1client "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"

	"github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/storagemigrate"
)

const podtraceAPIGroup = "podtrace.io"

func newMigrateStorageCmd() *cobra.Command {
	var (
		crdNames []string
		dryRun   bool
		access   kubernetes.ClusterAccess
	)

	cmd := &cobra.Command{
		Use:   "migrate-storage",
		Short: "Rewrite podtrace custom resources into the current CRD storage version",
		Long: `Rewrite stored custom resources into their CRD's current storage version,
then drop the versions that no longer hold any data from status.storedVersions.

Moving storage: true to a new CRD version does not rewrite anything. Existing
objects stay in etcd in the encoding they were written with, and Kubernetes
keeps every previously-used version pinned in spec.versions until no data
remains in it. This command performs that rewrite: it reads each object and
writes it back unchanged, which makes the API server re-encode it.

The operation is idempotent. Running it twice is the same as running it once,
and running it against an already-migrated CRD does nothing. It is step 2 and
3 of the cutover described in docs/api-versioning.md.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := context.Background()

			cfg, _, err := access.RESTConfig()
			if err != nil {
				return err
			}
			ext, err := apiextensionsclient.NewForConfig(cfg)
			if err != nil {
				return fmt.Errorf("apiextensions client: %w", err)
			}
			dyn, err := dynamic.NewForConfig(cfg)
			if err != nil {
				return fmt.Errorf("dynamic client: %w", err)
			}

			targets := crdNames
			if len(targets) == 0 {
				targets, err = podtraceCRDNames(ctx, ext.ApiextensionsV1().CustomResourceDefinitions())
				if err != nil {
					return err
				}
			}
			if len(targets) == 0 {
				return fmt.Errorf("no %s CRDs found in the cluster", podtraceAPIGroup)
			}

			return runMigrations(ctx, cmd.OutOrStdout(), ext.ApiextensionsV1().CustomResourceDefinitions(), dyn, targets, dryRun)
		},
	}

	cmd.Flags().StringSliceVar(&crdNames, "crd", nil,
		"CRD to migrate, repeatable (default: every "+podtraceAPIGroup+" CRD in the cluster)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"Report what would be rewritten without writing anything")
	cmd.Flags().StringVar(&access.Kubeconfig, "kubeconfig", "",
		"Path to a kubeconfig file (defaults to KUBECONFIG, then ~/.kube/config, then the in-cluster ServiceAccount)")
	cmd.Flags().StringVar(&access.Context, "context", "",
		"Kubeconfig context to use (defaults to the current context)")

	return cmd
}

func runMigrations(ctx context.Context, out io.Writer, crds storagemigrate.CRDClient, dyn dynamic.Interface, names []string, dryRun bool) error {
	var failures []string
	for _, name := range names {
		res, err := storagemigrate.Migrate(ctx, crds, dyn, name, dryRun)
		if err != nil {
			_, _ = fmt.Fprintf(out, "%s: %v\n", name, err)
			failures = append(failures, name)
			continue
		}
		_, _ = fmt.Fprintln(out, formatResult(res, dryRun))
	}
	if len(failures) > 0 {
		return fmt.Errorf("migration failed for %d CRD(s): %s", len(failures), strings.Join(failures, ", "))
	}
	return nil
}

func formatResult(res storagemigrate.Result, dryRun bool) string {
	verb := "rewrote"
	count := res.Rewritten
	if dryRun {
		verb = "would rewrite"
		count = res.Objects
	}

	line := fmt.Sprintf("%s: storage version %s, %d object(s), %s %d",
		res.CRD, res.StorageVersion, res.Objects, verb, count)
	if res.Conflicts > 0 {
		line += fmt.Sprintf(", %d changed under us (re-run)", res.Conflicts)
	}
	switch {
	case len(res.Unpinned) == 0:
		line += "; storedVersions already clean"
	case dryRun:
		line += fmt.Sprintf("; would unpin %s", strings.Join(res.Unpinned, ", "))
	default:
		line += fmt.Sprintf("; unpinned %s", strings.Join(res.Unpinned, ", "))
	}
	return line
}

func podtraceCRDNames(ctx context.Context, client apiextensionsv1client.CustomResourceDefinitionInterface) ([]string, error) {
	list, err := client.List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list CRDs: %w", err)
	}
	var names []string
	for _, crd := range list.Items {
		if crd.Spec.Group == podtraceAPIGroup {
			names = append(names, crd.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}
