package kubernetes

import (
	"context"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ServiceInfo struct {
	Name      string
	Namespace string
	Port      int
}

type ServiceResolver struct {
	clientset    kubernetes.Interface
	endpointCache *sync.Map
	cacheTTL     time.Duration
}

type endpointCacheEntry struct {
	serviceInfo ServiceInfo
	expiresAt   time.Time
}

func NewServiceResolver(clientset kubernetes.Interface) *ServiceResolver {
	ttl := time.Duration(getIntEnvOrDefault("PODTRACE_K8S_CACHE_TTL", 300)) * time.Second
	return &ServiceResolver{
		clientset:     clientset,
		endpointCache: &sync.Map{},
		cacheTTL:      ttl,
	}
}

func (sr *ServiceResolver) ResolveService(ctx context.Context, ip string, port int) *ServiceInfo {
	if ip == "" || port == 0 || sr.clientset == nil {
		return nil
	}

	cacheKey := fmt.Sprintf("%s:%d", ip, port)
	if cached, ok := sr.endpointCache.Load(cacheKey); ok {
		entry := cached.(*endpointCacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return &entry.serviceInfo
		}
		sr.endpointCache.Delete(cacheKey)
	}

	serviceInfo := sr.fetchServiceByEndpoint(ctx, ip, port)
	if serviceInfo != nil {
		sr.endpointCache.Store(cacheKey, &endpointCacheEntry{
			serviceInfo: *serviceInfo,
			expiresAt:   time.Now().Add(sr.cacheTTL),
		})
	}

	return serviceInfo
}

func (sr *ServiceResolver) fetchServiceByEndpoint(ctx context.Context, ip string, port int) *ServiceInfo {
	namespaces, err := sr.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	for _, ns := range namespaces.Items {
		endpoints, err := sr.clientset.CoreV1().Endpoints(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, endpoint := range endpoints.Items {
			for _, subset := range endpoint.Subsets {
				for _, addr := range subset.Addresses {
					if addr.IP == ip {
						for _, epPort := range subset.Ports {
							if int(epPort.Port) == port {
								return &ServiceInfo{
									Name:      endpoint.Name,
									Namespace: endpoint.Namespace,
									Port:      port,
								}
							}
						}
					}
				}
			}
		}
	}

	return nil
}

