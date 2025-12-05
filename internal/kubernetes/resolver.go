package kubernetes

import "context"

type PodResolverInterface interface {
	ResolvePod(ctx context.Context, podName, namespace, containerName string) (*PodInfo, error)
}

