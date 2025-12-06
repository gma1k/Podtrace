package kubernetes

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/podtrace/podtrace/internal/events"
)

type KubernetesContext struct {
	SourceNamespace   string
	SourceLabels      map[string]string
	TargetNamespace   string
	TargetPodName     string
	TargetLabels      map[string]string
	ServiceName       string
	ServiceNamespace  string
	IsExternal        bool
}

type EnrichedEvent struct {
	*events.Event
	KubernetesContext *KubernetesContext
}

type PodMetadata struct {
	Name      string
	Namespace string
	Labels    map[string]string
	IP        string
}

type ServiceMetadata struct {
	Name      string
	Namespace string
	Port      int
}

type cacheEntry struct {
	data      interface{}
	expiresAt time.Time
}

type ContextEnricher struct {
	clientset     kubernetes.Interface
	podCache      *sync.Map
	serviceCache  *sync.Map
	podInfo       *PodInfo
	serviceResolver *ServiceResolver
	cacheTTL      time.Duration
}

func NewContextEnricher(clientset kubernetes.Interface, podInfo *PodInfo) *ContextEnricher {
	ttl := time.Duration(getIntEnvOrDefault("PODTRACE_K8S_CACHE_TTL", 300)) * time.Second
	return &ContextEnricher{
		clientset:      clientset,
		podCache:       &sync.Map{},
		serviceCache:   &sync.Map{},
		podInfo:        podInfo,
		serviceResolver: NewServiceResolver(clientset),
		cacheTTL:       ttl,
	}
}

func (ce *ContextEnricher) EnrichEvent(ctx context.Context, event *events.Event) *EnrichedEvent {
	if event == nil {
		return nil
	}

	enriched := &EnrichedEvent{
		Event: event,
		KubernetesContext: &KubernetesContext{
			SourceNamespace: ce.podInfo.Namespace,
			SourceLabels:     ce.podInfo.Labels,
		},
	}

	if event.Target == "" || event.Target == "?" || event.Target == "unknown" || event.Target == "file" {
		return enriched
	}

	if isNetworkEvent(event.Type) {
		ip, port := parseTarget(event.Target)
		if ip != "" {
			ce.enrichNetworkTarget(ctx, enriched, ip, port)
		}
	}

	return enriched
}

func (ce *ContextEnricher) enrichNetworkTarget(ctx context.Context, enriched *EnrichedEvent, ip string, port int) {
	timeout := time.Duration(getIntEnvOrDefault("PODTRACE_K8S_API_TIMEOUT_MS", 100)) * time.Millisecond
	enrichCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	serviceInfo := ce.serviceResolver.ResolveService(enrichCtx, ip, port)
	if serviceInfo != nil {
		enriched.KubernetesContext.ServiceName = serviceInfo.Name
		enriched.KubernetesContext.ServiceNamespace = serviceInfo.Namespace
		return
	}

	podMeta := ce.resolvePodByIP(enrichCtx, ip)
	if podMeta != nil {
		enriched.KubernetesContext.TargetPodName = podMeta.Name
		enriched.KubernetesContext.TargetNamespace = podMeta.Namespace
		enriched.KubernetesContext.TargetLabels = podMeta.Labels
		return
	}

	if !isPrivateIP(ip) {
		enriched.KubernetesContext.IsExternal = true
	}
}

func (ce *ContextEnricher) resolvePodByIP(ctx context.Context, ip string) *PodMetadata {
	if ip == "" {
		return nil
	}

	if cached, ok := ce.podCache.Load(ip); ok {
		entry := cached.(*cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.data.(*PodMetadata)
		}
		ce.podCache.Delete(ip)
	}

	podMeta := ce.fetchPodByIP(ctx, ip)
	if podMeta != nil {
		ce.podCache.Store(ip, &cacheEntry{
			data:      podMeta,
			expiresAt: time.Now().Add(ce.cacheTTL),
		})
	}

	return podMeta
}

func (ce *ContextEnricher) fetchPodByIP(ctx context.Context, ip string) *PodMetadata {
	if ce.clientset == nil {
		return nil
	}

	namespaces, err := ce.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	for _, ns := range namespaces.Items {
		pods, err := ce.clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{
			FieldSelector: fmt.Sprintf("status.podIP=%s", ip),
		})
		if err != nil {
			continue
		}

		for _, pod := range pods.Items {
			if pod.Status.PodIP == ip {
				labels := make(map[string]string)
				if pod.Labels != nil {
					for k, v := range pod.Labels {
						labels[k] = v
					}
				}
				return &PodMetadata{
					Name:      pod.Name,
					Namespace: pod.Namespace,
					Labels:    labels,
					IP:        pod.Status.PodIP,
				}
			}
		}
	}

	return nil
}

func parseTarget(target string) (string, int) {
	if target == "" {
		return "", 0
	}

	if strings.HasPrefix(target, "[") {
		idx := strings.Index(target, "]")
		if idx > 0 {
			ip := target[1:idx]
			portStr := target[idx+2:]
			var port int
			_, _ = fmt.Sscanf(portStr, "%d", &port)
			return ip, port
		}
	}

	parts := strings.Split(target, ":")
	if len(parts) == 2 {
		var port int
		_, _ = fmt.Sscanf(parts[1], "%d", &port)
		return parts[0], port
	}

	return target, 0
}

func isNetworkEvent(eventType events.EventType) bool {
	return eventType == events.EventConnect ||
		eventType == events.EventTCPSend ||
		eventType == events.EventTCPRecv ||
		eventType == events.EventUDPSend ||
		eventType == events.EventUDPRecv ||
		eventType == events.EventTCPState ||
		eventType == events.EventTCPRetrans
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsPrivate()
}

func getIntEnvOrDefault(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	if i, err := strconv.Atoi(value); err == nil && i > 0 {
		return i
	}
	return defaultValue
}

