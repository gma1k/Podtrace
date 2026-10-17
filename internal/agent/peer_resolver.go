package agent

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	"github.com/gma1k/podtrace/internal/workloadmetrics"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The far end of an edge.
//
// A service map is only useful if both ends of a connection have a name that
// survives a rollout. The near end is the workload the metrics plane already
// resolves from the cgroup; this file supplies the far end, by asking which
// Service has the peer address as an endpoint.
const (
	PeerExternal = "external"
)

type PeerIdentity = workloadmetrics.PeerIdentity

const endpointIPIndex = "podtrace.peer.endpointIPPort"

const serviceIPIndex = "podtrace.peer.serviceIPPort"

// endpointKey is the indexed form of a peer address and port.
func endpointKey(ip string, port uint16) string {
	return ip + ":" + strconv.FormatUint(uint64(port), 10)
}

const (
	peerCacheTTL = 2 * time.Minute

	peerNegativeCacheTTL = 20 * time.Second

	peerCacheMaxEntries = 4096
)

type cachedPeer struct {
	identity PeerIdentity
	expires  time.Time
}

// PeerResolver turns a peer address into a Service identity, with a bounded
// TTL cache in front so the metrics hot path pays a map lookup rather than
// an index query per event.
type PeerResolver struct {
	mu      sync.Mutex
	entries map[string]cachedPeer

	lookup func(ip string, port uint16) (PeerIdentity, bool)

	ttl         time.Duration
	negativeTTL time.Duration
	max         int
	now         func() time.Time
}

// NewPeerResolver builds a resolver over an uncached lookup.
func NewPeerResolver(lookup func(ip string, port uint16) (PeerIdentity, bool)) *PeerResolver {
	return &PeerResolver{
		entries:     map[string]cachedPeer{},
		lookup:      lookup,
		ttl:         peerCacheTTL,
		negativeTTL: peerNegativeCacheTTL,
		max:         peerCacheMaxEntries,
		now:         time.Now,
	}
}

// Resolve names the far end of an edge, reporting false when there is
// nothing drawable to name.
func (r *PeerResolver) Resolve(ip string, port uint16) (PeerIdentity, bool) {
	if r == nil || ip == "" {
		return PeerIdentity{}, false
	}

	key := endpointKey(ip, port)
	now := r.now()

	r.mu.Lock()
	if entry, ok := r.entries[key]; ok && now.Before(entry.expires) {
		r.mu.Unlock()
		return entry.identity, entry.identity.Service != ""
	}
	r.mu.Unlock()

	identity, resolved := PeerIdentity{}, false
	if r.lookup != nil {
		identity, resolved = r.lookup(ip, port)
	}
	ttl := r.ttl
	if !resolved {
		identity = PeerIdentity{Service: undrawablePeer(ip)}
		ttl = r.negativeTTL
	}

	r.store(key, identity, now.Add(ttl), now)
	return identity, identity.Service != ""
}

// store caches a resolution, dropping expired entries before deciding the
// cache is full.
func (r *PeerResolver) store(ip string, identity PeerIdentity, expires, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, replacing := r.entries[ip]; !replacing && len(r.entries) >= r.max {
		for key, entry := range r.entries {
			if !now.Before(entry.expires) {
				delete(r.entries, key)
			}
		}
		if len(r.entries) >= r.max {
			return
		}
	}
	r.entries[ip] = cachedPeer{identity: identity, expires: expires}
}

// size reports how many resolutions are cached. Tests only.
func (r *PeerResolver) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// undrawablePeer decides what an address no Service claimed becomes.
func undrawablePeer(ip string) string {
	if isClusterLocalIP(ip) {
		return ""
	}
	return PeerExternal
}

// sharedAddressSpace is RFC 6598's 100.64.0.0/10. IsPrivate leaves it out,
// yet EKS custom networking, Calico and GKE alternate ranges hand it out as
// pod and node CIDRs, so an unresolved peer there is inside the cluster
// rather than external.
var sharedAddressSpace = &net.IPNet{
	IP:   net.IPv4(100, 64, 0, 0).To4(),
	Mask: net.CIDRMask(10, 32),
}

// isClusterLocalIP reports whether an address is one a cluster hands out.
func isClusterLocalIP(raw string) bool {
	ip := net.ParseIP(raw)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() ||
		sharedAddressSpace.Contains(ip) ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified()
}

// RegisterPeerIndex teaches the manager's cache to look EndpointSlices up by
// the addresses they carry.
func RegisterPeerIndex(ctx context.Context, mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(ctx, &discoveryv1.EndpointSlice{},
		endpointIPIndex, endpointIndexFunc()); err != nil {
		return err
	}
	return mgr.GetFieldIndexer().IndexField(ctx, &corev1.Service{},
		serviceIPIndex, serviceIndexFunc())
}

// serviceIndexFunc maps a Service to every "clusterIP:port" it answers on.
func serviceIndexFunc() client.IndexerFunc {
	return func(obj client.Object) []string {
		service, ok := obj.(*corev1.Service)
		if !ok {
			return nil
		}
		addresses := service.Spec.ClusterIPs
		if len(addresses) == 0 && service.Spec.ClusterIP != "" {
			addresses = []string{service.Spec.ClusterIP}
		}
		keys := make([]string, 0, len(addresses)*len(service.Spec.Ports))
		for _, address := range addresses {
			if address == "" || address == corev1.ClusterIPNone {
				continue
			}
			for _, port := range service.Spec.Ports {
				if port.Port < 0 || port.Port > 65535 {
					continue
				}
				keys = append(keys, endpointKey(address, uint16(port.Port)))
			}
		}
		return keys
	}
}

// trimService drops what the resolver never reads before a Service enters
// the cache.
func trimService(obj interface{}) (interface{}, error) {
	service, ok := obj.(*corev1.Service)
	if !ok {
		return obj, nil
	}
	service.ManagedFields = nil
	service.Annotations = nil
	service.OwnerReferences = nil
	service.Labels = nil
	service.Status = corev1.ServiceStatus{}
	return service, nil
}

// endpointIndexFunc maps an EndpointSlice to every address it carries, so a
// Service with several ready endpoints resolves from any of them.
func endpointIndexFunc() client.IndexerFunc {
	return func(obj client.Object) []string {
		slice, ok := obj.(*discoveryv1.EndpointSlice)
		if !ok {
			return nil
		}
		keys := make([]string, 0, len(slice.Endpoints)*len(slice.Ports))
		for _, endpoint := range slice.Endpoints {
			for _, address := range endpoint.Addresses {
				for _, port := range slice.Ports {
					if port.Port == nil || *port.Port < 0 || *port.Port > 65535 {
						continue
					}
					keys = append(keys, endpointKey(address, uint16(*port.Port)))
				}
			}
		}
		return keys
	}
}

// clusterPeerLookup resolves an address through the indexed cache, trying
// the backend endpoints first and the Service's own address second.
func clusterPeerLookup(reader client.Reader) func(ip string, port uint16) (PeerIdentity, bool) {
	byEndpoint := endpointSliceLookup(reader)
	byClusterIP := serviceLookup(reader)
	return func(ip string, port uint16) (PeerIdentity, bool) {
		if identity, ok := byEndpoint(ip, port); ok {
			return identity, true
		}
		return byClusterIP(ip, port)
	}
}

// serviceLookup resolves a ClusterIP through the indexed cache.
func serviceLookup(reader client.Reader) func(ip string, port uint16) (PeerIdentity, bool) {
	return func(ip string, port uint16) (PeerIdentity, bool) {
		if reader == nil {
			return PeerIdentity{}, false
		}
		var services corev1.ServiceList
		if err := reader.List(context.Background(), &services,
			client.MatchingFields{serviceIPIndex: endpointKey(ip, port)}); err != nil {
			return PeerIdentity{}, false
		}
		var best *corev1.Service
		for i := range services.Items {
			service := &services.Items[i]
			if best == nil || lessNamespacedName(service.Namespace, service.Name, best.Namespace, best.Name) {
				best = service
			}
		}
		if best == nil {
			return PeerIdentity{}, false
		}
		return PeerIdentity{Service: best.Name, Namespace: best.Namespace}, true
	}
}

// endpointSliceLookup resolves a backend address through the indexed cache.
func endpointSliceLookup(reader client.Reader) func(ip string, port uint16) (PeerIdentity, bool) {
	return func(ip string, port uint16) (PeerIdentity, bool) {
		if reader == nil {
			return PeerIdentity{}, false
		}
		var slices discoveryv1.EndpointSliceList
		if err := reader.List(context.Background(), &slices,
			client.MatchingFields{endpointIPIndex: endpointKey(ip, port)}); err != nil {
			return PeerIdentity{}, false
		}
		var best *discoveryv1.EndpointSlice
		for i := range slices.Items {
			slice := &slices.Items[i]
			if slice.Labels[discoveryv1.LabelServiceName] == "" {
				continue
			}
			if best == nil || preferSlice(slice, best) {
				best = slice
			}
		}
		if best == nil {
			return PeerIdentity{}, false
		}
		return PeerIdentity{Service: best.Labels[discoveryv1.LabelServiceName], Namespace: best.Namespace}, true
	}
}

const endpointSliceControllerName = "endpointslice-controller.k8s.io"

// preferSlice reports whether candidate names the far end better than
// current.
func preferSlice(candidate, current *discoveryv1.EndpointSlice) bool {
	_, candidateHeadless := candidate.Labels[corev1.IsHeadlessService]
	_, currentHeadless := current.Labels[corev1.IsHeadlessService]
	if candidateHeadless != currentHeadless {
		return !candidateHeadless
	}
	candidateManaged := candidate.Labels[discoveryv1.LabelManagedBy] == endpointSliceControllerName
	currentManaged := current.Labels[discoveryv1.LabelManagedBy] == endpointSliceControllerName
	if candidateManaged != currentManaged {
		return candidateManaged
	}
	return lessNamespacedName(
		candidate.Namespace, candidate.Labels[discoveryv1.LabelServiceName],
		current.Namespace, current.Labels[discoveryv1.LabelServiceName])
}

// lessNamespacedName orders (namespace, name) pairs so a tie between
// candidates resolves the same way on every node and every refresh.
func lessNamespacedName(namespace, name, otherNamespace, otherName string) bool {
	if namespace != otherNamespace {
		return namespace < otherNamespace
	}
	return name < otherName
}

// trimEndpointSlice drops the fields the resolver never reads before an
// EndpointSlice enters the cache.
func trimEndpointSlice(obj interface{}) (interface{}, error) {
	slice, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		return obj, nil
	}
	slice.ManagedFields = nil
	slice.Annotations = nil
	slice.OwnerReferences = nil
	if name, present := slice.Labels[discoveryv1.LabelServiceName]; present {
		kept := map[string]string{discoveryv1.LabelServiceName: name}
		for _, label := range []string{corev1.IsHeadlessService, discoveryv1.LabelManagedBy} {
			if value, present := slice.Labels[label]; present {
				kept[label] = value
			}
		}
		slice.Labels = kept
	} else {
		slice.Labels = nil
	}
	for i := range slice.Endpoints {
		slice.Endpoints[i].TargetRef = nil
		slice.Endpoints[i].Hostname = nil
		slice.Endpoints[i].DeprecatedTopology = nil
	}
	return slice, nil
}
