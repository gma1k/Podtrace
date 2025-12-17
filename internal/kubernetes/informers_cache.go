package kubernetes

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	podIPIndex     = "podIP"
	ipPortIndex    = "ipPort"
	ipOnlyIndex    = "ipOnly"
	serviceNameKey = "kubernetes.io/service-name"
)

type InformerCache struct {
	clientset kubernetes.Interface

	mu      sync.RWMutex
	started bool
	stopCh  chan struct{}

	podInf cache.SharedIndexInformer
	esInf  cache.SharedIndexInformer
}

func NewInformerCache(clientset kubernetes.Interface) *InformerCache {
	return &InformerCache{clientset: clientset}
}

func (ic *InformerCache) Enabled() bool {
	// Default enabled; can be disabled explicitly.
	return os.Getenv("PODTRACE_K8S_USE_INFORMERS") != "false"
}

func (ic *InformerCache) Start(ctx context.Context) {
	if ic == nil || ic.clientset == nil || !ic.Enabled() {
		return
	}

	ic.mu.Lock()
	if ic.started {
		ic.mu.Unlock()
		return
	}
	ic.started = true
	ic.stopCh = make(chan struct{})
	stopCh := ic.stopCh
	ic.mu.Unlock()

	resync := 0 * time.Second
	factory := informers.NewSharedInformerFactoryWithOptions(ic.clientset, resync, informers.WithNamespace(metav1.NamespaceAll))

	podInf := factory.Core().V1().Pods().Informer()
	_ = podInf.AddIndexers(cache.Indexers{
		podIPIndex: func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*corev1.Pod)
			if !ok || pod == nil {
				return nil, nil
			}
			if pod.Status.PodIP == "" {
				return nil, nil
			}
			return []string{pod.Status.PodIP}, nil
		},
	})

	esInf := factory.Discovery().V1().EndpointSlices().Informer()
	_ = esInf.AddIndexers(cache.Indexers{
		ipOnlyIndex: func(obj interface{}) ([]string, error) {
			es, ok := obj.(*discoveryv1.EndpointSlice)
			if !ok || es == nil {
				return nil, nil
			}
			var keys []string
			for _, ep := range es.Endpoints {
				for _, addr := range ep.Addresses {
					if addr != "" {
						keys = append(keys, addr)
					}
				}
			}
			return keys, nil
		},
		ipPortIndex: func(obj interface{}) ([]string, error) {
			es, ok := obj.(*discoveryv1.EndpointSlice)
			if !ok || es == nil {
				return nil, nil
			}
			var ports []int32
			for _, p := range es.Ports {
				if p.Port != nil {
					ports = append(ports, *p.Port)
				}
			}
			if len(ports) == 0 {
				return nil, nil
			}
			var keys []string
			for _, ep := range es.Endpoints {
				for _, addr := range ep.Addresses {
					if addr == "" {
						continue
					}
					for _, port := range ports {
						keys = append(keys, fmt.Sprintf("%s:%d", addr, port))
					}
				}
			}
			return keys, nil
		},
	})

	ic.mu.Lock()
	ic.podInf = podInf
	ic.esInf = esInf
	ic.mu.Unlock()

	factory.Start(stopCh)

	timeoutSec := 2
	if v := os.Getenv("PODTRACE_K8S_INFORMERS_SYNC_TIMEOUT_SEC"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			timeoutSec = i
		}
	}

	syncCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	synced := cache.WaitForCacheSync(syncCtx.Done(), podInf.HasSynced, esInf.HasSynced)
	_ = synced
}

func (ic *InformerCache) Stop() {
	if ic == nil {
		return
	}
	ic.mu.Lock()
	defer ic.mu.Unlock()
	if !ic.started {
		return
	}
	close(ic.stopCh)
	ic.started = false
}

func (ic *InformerCache) GetPodByIP(ip string) *PodMetadata {
	if ic == nil || ip == "" {
		return nil
	}
	ic.mu.RLock()
	inf := ic.podInf
	ic.mu.RUnlock()
	if inf == nil {
		return nil
	}
	objs, err := inf.GetIndexer().ByIndex(podIPIndex, ip)
	if err != nil || len(objs) == 0 {
		return nil
	}
	pod, ok := objs[0].(*corev1.Pod)
	if !ok || pod == nil {
		return nil
	}
	labels := make(map[string]string)
	for k, v := range pod.Labels {
		labels[k] = v
	}
	return &PodMetadata{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Labels:    labels,
		IP:        pod.Status.PodIP,
	}
}

func (ic *InformerCache) GetServiceByEndpoint(ip string, port int) *ServiceInfo {
	if ic == nil || ip == "" {
		return nil
	}
	ic.mu.RLock()
	inf := ic.esInf
	ic.mu.RUnlock()
	if inf == nil {
		return nil
	}

	var objs []interface{}
	var err error
	if port > 0 {
		key := fmt.Sprintf("%s:%d", ip, port)
		objs, err = inf.GetIndexer().ByIndex(ipPortIndex, key)
	} else {
		objs, err = inf.GetIndexer().ByIndex(ipOnlyIndex, ip)
	}
	if err != nil || len(objs) == 0 {
		return nil
	}

	es, ok := objs[0].(*discoveryv1.EndpointSlice)
	if !ok || es == nil {
		return nil
	}
	svcName := ""
	if es.Labels != nil {
		svcName = es.Labels[serviceNameKey]
		if svcName == "" {
			if v := es.Labels[discoveryv1.LabelServiceName]; v != "" {
				svcName = v
			}
		}
	}
	if svcName == "" {
		return nil
	}

	svcName = strings.TrimSpace(svcName)
	if svcName == "" {
		return nil
	}
	return &ServiceInfo{Name: svcName, Namespace: es.Namespace, Port: port}
}
