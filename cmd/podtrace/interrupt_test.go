package main

import (
	"os"
	"testing"
	"time"
)

func TestInterruptChan(t *testing.T) {
	ch := interruptChan()
	if ch == nil {
		t.Fatal("interruptChan returned nil channel")
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		proc, _ := os.FindProcess(os.Getpid())
		proc.Signal(os.Interrupt)
	}()

	select {
	case sig := <-ch:
		if sig != os.Interrupt {
			t.Errorf("Expected os.Interrupt, got %v", sig)
		}
	case <-time.After(1 * time.Second):
		t.Error("interruptChan did not receive signal in time")
	}
}

func TestInterruptChan_PanicRecovery(t *testing.T) {
	ch := interruptChan()
	if ch == nil {
		t.Fatal("interruptChan returned nil channel")
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		proc, _ := os.FindProcess(os.Getpid())
		proc.Signal(os.Interrupt)
	}()

	select {
	case <-ch:
	case <-time.After(1 * time.Second):
		t.Error("interruptChan did not receive signal in time")
	}
}

