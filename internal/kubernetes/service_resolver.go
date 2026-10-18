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
	cacheTTL      time.Duration
	negativeTTL   time.Duration
	informerCache *InformerCache

	mu                sync.RWMutex
	endpoints         map[string]ServiceInfo
	endpointsExpireAt time.Time
	notFound          map[string]time.Time

	fetchMu sync.Mutex
}

// endpointsPageSize bounds one page of the cluster-wide Endpoints listing.
const endpointsPageSize = 500

func NewServiceResolver(clientset kubernetes.Interface) *ServiceResolver {
	return NewServiceResolverWithCache(clientset, nil)
}

func NewServiceResolverWithCache(clientset kubernetes.Interface, ic *InformerCache) *ServiceResolver {
	ttl := time.Duration(getIntEnvOrDefault("PODTRACE_K8S_CACHE_TTL", 300)) * time.Second
	negativeTTL := 30 * time.Second
	if negativeTTL > ttl {
		negativeTTL = ttl
	}
	return &ServiceResolver{
		clientset:     clientset,
		cacheTTL:      ttl,
		negativeTTL:   negativeTTL,
		informerCache: ic,
		notFound:      map[string]time.Time{},
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
		return sr.informerCache.GetServiceByEndpoint(ip, port)
	}

	cacheKey := endpointKey(ip, port)
	if info, ok := sr.lookupCache(cacheKey); ok {
		return info
	}

	sr.fetchMu.Lock()
	defer sr.fetchMu.Unlock()
	if info, ok := sr.lookupCache(cacheKey); ok {
		return info
	}
	return sr.fetchServiceByEndpoint(ctx, ip, port)
}

func endpointKey(ip string, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

// lookupCache returns (info, true) on a live positive hit, (nil, true) on
// a live negative hit, and (nil, false) when the resolver must fetch.
func (sr *ServiceResolver) lookupCache(cacheKey string) (*ServiceInfo, bool) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	now := time.Now()
	if now.Before(sr.endpointsExpireAt) {
		if info, ok := sr.endpoints[cacheKey]; ok {
			return &info, true
		}
	}
	if until, ok := sr.notFound[cacheKey]; ok && now.Before(until) {
		return nil, true
	}
	return nil, false
}

// fetchServiceByEndpoint lists every Endpoints object page by page and
// replaces the positive cache with the result, so one cluster-wide listing
// serves every lookup until it expires. A miss is remembered for the
// shorter negative TTL, and expired misses are pruned on each refresh.
func (sr *ServiceResolver) fetchServiceByEndpoint(ctx context.Context, ip string, port int) *ServiceInfo {
	cacheKey := endpointKey(ip, port)
	next, err := sr.listEndpoints(ctx)
	now := time.Now()

	sr.mu.Lock()
	defer sr.mu.Unlock()
	if err == nil {
		sr.endpoints = next
		sr.endpointsExpireAt = now.Add(sr.cacheTTL)
	}
	for key, until := range sr.notFound {
		if !now.Before(until) {
			delete(sr.notFound, key)
		}
	}
	if err == nil {
		if info, ok := next[cacheKey]; ok {
			return &info
		}
	}
	if sr.notFound == nil {
		sr.notFound = map[string]time.Time{}
	}
	sr.notFound[cacheKey] = now.Add(sr.negativeTTL)
	return nil
}

func (sr *ServiceResolver) listEndpoints(ctx context.Context) (map[string]ServiceInfo, error) {
	out := map[string]ServiceInfo{}
	opts := metav1.ListOptions{Limit: endpointsPageSize}
	for {
		page, err := sr.clientset.CoreV1().Endpoints(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return nil, err
		}
		for _, endpoint := range page.Items {
			for _, subset := range endpoint.Subsets {
				for _, addr := range subset.Addresses {
					for _, epPort := range subset.Ports {
						key := endpointKey(addr.IP, int(epPort.Port))
						if _, seen := out[key]; seen {
							continue
						}
						out[key] = ServiceInfo{Name: endpoint.Name, Namespace: endpoint.Namespace, Port: int(epPort.Port)}
					}
				}
			}
		}
		if page.Continue == "" {
			return out, nil
		}
		opts.Continue = page.Continue
	}
}
