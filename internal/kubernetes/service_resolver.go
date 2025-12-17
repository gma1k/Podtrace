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
	clientset     kubernetes.Interface
	endpointCache *sync.Map
	cacheTTL      time.Duration
	informerCache *InformerCache
}

type endpointCacheEntry struct {
	serviceInfo ServiceInfo
	expiresAt   time.Time
}

func NewServiceResolver(clientset kubernetes.Interface) *ServiceResolver {
	return NewServiceResolverWithCache(clientset, nil)
}

func NewServiceResolverWithCache(clientset kubernetes.Interface, ic *InformerCache) *ServiceResolver {
	ttl := time.Duration(getIntEnvOrDefault("PODTRACE_K8S_CACHE_TTL", 300)) * time.Second
	return &ServiceResolver{
		clientset:     clientset,
		endpointCache: &sync.Map{},
		cacheTTL:      ttl,
		informerCache: ic,
	}
}

func (sr *ServiceResolver) ResolveService(ctx context.Context, ip string, port int) *ServiceInfo {
	if ip == "" || port == 0 || sr.clientset == nil {
		if sr.informerCache != nil && ip != "" {
			return sr.informerCache.GetServiceByEndpoint(ip, port)
		}
		return nil
	}

	if sr.informerCache != nil {
		if svc := sr.informerCache.GetServiceByEndpoint(ip, port); svc != nil {
			return svc
		}
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
	endpointsList, err := sr.clientset.CoreV1().Endpoints(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	for _, endpoint := range endpointsList.Items {
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

	return nil
}
