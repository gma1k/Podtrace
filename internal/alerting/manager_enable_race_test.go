package alerting

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestEnsureEnabledRacesNoReaders(t *testing.T) {
	enableAlerting(t)
	m := &Manager{enabled: false}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 200; j++ {
				m.SendAlert(deliveryTestAlert())
				_ = m.IsEnabled()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		m.EnsureEnabledWithSender(&mockSender{name: "late"})
	}()
	close(start)
	wg.Wait()
	if !m.IsEnabled() {
		t.Fatal("manager must be enabled after EnsureEnabledWithSender")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
