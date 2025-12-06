package kubernetes

import (
	"context"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
)

type K8sEvent struct {
	Type      string
	Reason    string
	Message   string
	Timestamp time.Time
	Count     int32
}

type EventsCorrelator struct {
	clientset    kubernetes.Interface
	podName      string
	namespace    string
	events       []*K8sEvent
	mu           sync.RWMutex
	eventWatcher watch.Interface
	stopCh       chan struct{}
}

func NewEventsCorrelator(clientset kubernetes.Interface, podName, namespace string) *EventsCorrelator {
	return &EventsCorrelator{
		clientset: clientset,
		podName:   podName,
		namespace: namespace,
		events:    make([]*K8sEvent, 0),
		stopCh:    make(chan struct{}),
	}
}

func (ec *EventsCorrelator) Start(ctx context.Context) error {
	if ec.clientset == nil {
		return nil
	}

	watcher, err := ec.clientset.CoreV1().Events(ec.namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector: "involvedObject.name=" + ec.podName,
	})
	if err != nil {
		return err
	}

	ec.eventWatcher = watcher

	go ec.watchEvents(ctx)
	return nil
}

func (ec *EventsCorrelator) watchEvents(ctx context.Context) {
	defer func() {
		if ec.eventWatcher != nil {
			ec.eventWatcher.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ec.stopCh:
			return
		case event, ok := <-ec.eventWatcher.ResultChan():
			if !ok {
				return
			}

			if k8sEvent, ok := event.Object.(*corev1.Event); ok {
				ec.addEvent(k8sEvent)
			}
		}
	}
}

func (ec *EventsCorrelator) addEvent(event *corev1.Event) {
	if event.InvolvedObject.Name != ec.podName {
		return
	}

	ec.mu.Lock()
	defer ec.mu.Unlock()

	k8sEvent := &K8sEvent{
		Type:      event.Type,
		Reason:    event.Reason,
		Message:   event.Message,
		Timestamp: event.FirstTimestamp.Time,
		Count:     event.Count,
	}

	ec.events = append(ec.events, k8sEvent)

	maxEvents := 100
	if len(ec.events) > maxEvents {
		ec.events = ec.events[len(ec.events)-maxEvents:]
	}
}

func (ec *EventsCorrelator) GetEvents() []*K8sEvent {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	result := make([]*K8sEvent, len(ec.events))
	copy(result, ec.events)
	return result
}

func (ec *EventsCorrelator) Stop() {
	close(ec.stopCh)
	if ec.eventWatcher != nil {
		ec.eventWatcher.Stop()
	}
}

func (ec *EventsCorrelator) CorrelateWithAppEvents(appEventTime time.Time, window time.Duration) []*K8sEvent {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	var correlated []*K8sEvent
	windowStart := appEventTime.Add(-window)
	windowEnd := appEventTime.Add(window)

	for _, k8sEvent := range ec.events {
		if k8sEvent.Timestamp.After(windowStart) && k8sEvent.Timestamp.Before(windowEnd) {
			correlated = append(correlated, k8sEvent)
		}
	}

	return correlated
}

