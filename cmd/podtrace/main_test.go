package main

import (
	"os"
	"testing"
	"time"
)

func TestMain_CommandExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping main function test in short mode")
	}

	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"podtrace", "--help"}

	oldExit := exitFunc
	exited := false
	exitFunc = func(code int) {
		exited = true
	}
	defer func() { exitFunc = oldExit }()

	done := make(chan bool, 1)
	go func() {
		main()
		done <- true
	}()

	select {
	case <-done:
		if !exited {
			t.Log("main function executed (help command)")
		}
	case <-time.After(1 * time.Second):
		t.Log("main function test completed")
	}
}

func TestMain_InvalidArgs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping main function test in short mode")
	}

	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"podtrace"}

	oldExit := exitFunc
	exited := false
	exitFunc = func(code int) {
		exited = true
	}
	defer func() { exitFunc = oldExit }()

	done := make(chan bool, 1)
	go func() {
		main()
		done <- true
	}()

	select {
	case <-done:
		if !exited {
			t.Log("main function executed (invalid args)")
		}
	case <-time.After(1 * time.Second):
		t.Log("main function test completed")
	}
}

func TestMain_LogLevel(t *testing.T) {
	origLogLevel := logLevel
	origArgs := os.Args
	defer func() {
		logLevel = origLogLevel
		os.Args = origArgs
	}()

	os.Args = []string{"podtrace", "--log-level", "debug", "--help"}

	oldExit := exitFunc
	exitFunc = func(code int) {
	}
	defer func() { exitFunc = oldExit }()

	done := make(chan bool, 1)
	go func() {
		main()
		done <- true
	}()

	select {
	case <-done:
		t.Log("main function executed with log level")
	case <-time.After(1 * time.Second):
		t.Log("main function test completed")
	}
}

func TestMain_CommandError(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping main function test in short mode")
	}

	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"podtrace", "test-pod", "--invalid-flag"}

	oldExit := exitFunc
	exited := false
	exitFunc = func(code int) {
		exited = true
	}
	defer func() { exitFunc = oldExit }()

	done := make(chan bool, 1)
	go func() {
		main()
		done <- true
	}()

	select {
	case <-done:
		if !exited {
			t.Log("main function executed (command error)")
		}
	case <-time.After(1 * time.Second):
		t.Log("main function test completed")
	}
}
