package kubernetes

import "k8s.io/client-go/kubernetes"

func NewPodResolverForTesting(clientset kubernetes.Interface) *PodResolver {
	return &PodResolver{
		clientset: clientset,
	}
}

