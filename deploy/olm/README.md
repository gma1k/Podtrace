# OLM bundle source

Hand-authored sources for podtrace's [Operator Lifecycle Manager (OLM)](https://olm.operatorframework.io/)
bundle published to [OperatorHub.io](https://operatorhub.io/) via the
[community-operators](https://github.com/k8s-operatorhub/community-operators)
catalog.

## Files

| File | Purpose |
|------|---------|
| `csv-template.yaml` | ClusterServiceVersion template with `__VERSION__`, `__PREVIOUS_VERSION__`, `__CREATED_AT__`, `__SKIP_RANGE_UPPER__` placeholders. The single hand-authored file describing the operator to OLM. |
| `annotations.yaml` | Bundle metadata (channel, package, mediatype). Stable across releases. |
| `bundle.Dockerfile.template` | Bundle image Dockerfile. Stable across releases; `__VERSION__` is substituted at build time for labels only. |

## Build flow

```
chart templates/crds/ ─┐
                       ├─► scripts/build-olm-bundle.sh ─► bundle/<version>/
csv-template.yaml ─────┤                                    manifests/
                       │                                      *.crd.yaml
annotations.yaml ──────┤                                      podtrace.csv.yaml
                       │                                    metadata/
bundle.Dockerfile.tpl ─┘                                      annotations.yaml
                                                            bundle.Dockerfile
```

The CRDs are copied from the Helm chart (`deploy/charts/podtrace/`). The
operator's RBAC and Deployment in `csv-template.yaml` are a hand-maintained
copy of what the chart renders, because OLM wants them inline in the CSV.

That copy is held to the chart by `test/chart/olm_csv_drift_test.go`, which
renders the chart and fails when the CSV's cluster permissions, namespaced
permissions, rollout strategy, pod and container security contexts, image,
args, env, ports or probes differ from it. Change the chart first, then make
the same change here; the Chart CI workflow runs the test on every PR that
touches either. Resource requests and limits are deliberately not compared.

When `IMAGE_DIGEST` is set (the release workflow always sets it), the build
script references the operator image by digest instead of by tag.

## Output (gitignored)

`bundle/<version>/` is generated per-release. Contents are copied into
the contributor's fork of `k8s-operatorhub/community-operators` under
`operators/podtrace/<version>/` for submission.

## Validation

After build:

```bash
operator-sdk bundle validate ./bundle/<version> --select-optional name=community
```

This runs the same checks community-operators CI runs.

## Local end-to-end on kind

```bash
make bundle-build bundle-push VERSION=v0.11.7
operator-sdk olm install
operator-sdk run bundle ghcr.io/gma1k/podtrace-bundle:v0.11.7 \
  --install-mode AllNamespaces --namespace podtrace-system
```
