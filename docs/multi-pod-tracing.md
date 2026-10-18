# Multi-Pod Tracing

## Overview

Podtrace supports tracing multiple pods at once, including pods across different namespaces.

You can target pods using:

- A single positional pod name (`<pod-name>`) for backward compatibility
- Explicit pod list (`--pods`)
- Label selector (`--pod-selector`)
- Namespace-wide selection (`--all-in-namespace`)
- Multi-namespace selection (`--namespaces`)

Podtrace keeps targets updated while it runs. If matching pods are added or removed, target cgroup filters are updated automatically.

## Target Selection Modes

### 1) Single pod (legacy mode)

```bash
./bin/podtrace -n podtrace-test nginx-test --diagnose 30s
```

### 2) Explicit pod list

Supports both `pod` and `namespace/pod` forms.

```bash
./bin/podtrace --namespace podtrace-test \
  --pods alpine-test,busybox-test \
  --diagnose 30s

./bin/podtrace --pods podtrace-test/alpine-test,podtrace-cross/nginx-cross \
  --diagnose 30s
```

### 3) All pods in one namespace

```bash
./bin/podtrace --namespace podtrace-test --all-in-namespace --diagnose 45s
```

### 4) Label selector (single namespace)

```bash
./bin/podtrace --namespace podtrace-test --pod-selector app=podtrace-e2e --diagnose 45s
```

### 5) Cross-namespace selector

```bash
./bin/podtrace \
  --namespaces podtrace-test,podtrace-cross \
  --pod-selector app=podtrace-e2e \
  --diagnose 60s
```

## How the Selection Flags Combine

The default spawn mode and `--local` select pods with the same rules:

- Named pods (`<pod-name>` or `--pods`) are the target set. A `namespace/pod`
  ref carries its own namespace; a bare name uses `--namespace`.
- `--pod-selector` narrows named pods: only those whose labels match are traced.
  Without named pods, it selects every matching pod in the namespaces in scope.
- `--namespaces` sets the namespaces a selector or `--all-in-namespace` looks in.
  A named pod outside that list is an error rather than silently skipped.
- `--all-namespaces` looks in every namespace, so named pods need the
  `namespace/pod` form.
- A pod with no running container yet is skipped with a warning; if no
  selected pod is running, the command fails and says so.

## Same-Namespace Test Flow

Use this to verify multi-pod tracing quickly.

1. Ensure service DNS exists:

```bash
kubectl -n podtrace-test expose pod nginx-test --name nginx-test --port 80 --target-port 80
kubectl -n podtrace-test get svc,endpoints
```

2. Start Podtrace:

```bash
sudo -E env "KUBECONFIG=$HOME/.kube/config" ./bin/podtrace \
  --namespace podtrace-test \
  --all-in-namespace \
  --filter net,dns \
  --diagnose 45s
```

3. Generate traffic:

```bash
kubectl -n podtrace-test exec alpine-test -- sh -c 'for i in $(seq 1 50); do wget -q -O- http://nginx-test >/dev/null; nslookup nginx-test >/dev/null 2>&1; sleep 0.2; done'
kubectl -n podtrace-test exec busybox-test -- sh -c 'for i in $(seq 1 50); do wget -q -O- http://nginx-test >/dev/null; sleep 0.2; done'
```

## Cross-Namespace Test Flow

1. Create second namespace and service:

```bash
kubectl create ns podtrace-cross
kubectl -n podtrace-cross run nginx-cross --image=nginx:1.27 --labels app=podtrace-e2e --port 80
kubectl -n podtrace-cross expose pod nginx-cross --name nginx-cross --port 80
kubectl -n podtrace-test label pod alpine-test app=podtrace-e2e --overwrite
kubectl -n podtrace-test label pod busybox-test app=podtrace-e2e --overwrite
```

2. Start Podtrace with cross-namespace selection:

```bash
sudo -E env "KUBECONFIG=$HOME/.kube/config" ./bin/podtrace \
  --namespaces podtrace-test,podtrace-cross \
  --pod-selector app=podtrace-e2e \
  --filter net,dns \
  --diagnose 60s
```

3. Generate cross-namespace traffic:

```bash
kubectl -n podtrace-test exec alpine-test -- sh -c 'for i in $(seq 1 80); do wget -q -O- http://nginx-cross.podtrace-cross.svc.cluster.local >/dev/null; sleep 0.2; done'
```

## Dynamic Target Updates

When Podtrace runs with selector or namespace-wide targeting, it updates targets at runtime.

Quick check:

```bash
kubectl -n podtrace-test run late-joiner --image=busybox --labels app=podtrace-e2e --restart=Never -- sh -c 'sleep 300'
kubectl -n podtrace-test delete pod late-joiner
```

You should see target set refresh logs while Podtrace is running.

## Troubleshooting

### `wget: bad address 'nginx-test'`

This means DNS name `nginx-test` has no Service backing it in that namespace.

Fix:

```bash
kubectl -n podtrace-test expose pod nginx-test --name nginx-test --port 80 --target-port 80
```

### No events for selected pods

- Verify selected pods are `Running`
- Verify generated traffic actually originates from selected pods
- Verify selector matches expected pods:

```bash
kubectl get pods -n podtrace-test -l app=podtrace-e2e
```

- In cross-namespace mode, verify all namespaces exist and are listed correctly
