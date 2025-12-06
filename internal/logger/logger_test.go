package logger

import (
	"os"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestLogger(t *testing.T) {
	log := Logger()
	if log == nil {
		t.Error("Logger() should not return nil")
	}
}

func TestSetLevel(t *testing.T) {
	originalLevel := atomicLevel.Level()
	defer SetLevel(originalLevel.String())

	tests := []struct {
		name     string
		levelStr string
		expected zapcore.Level
	}{
		{"debug", "debug", zapcore.DebugLevel},
		{"info", "info", zapcore.InfoLevel},
		{"warn", "warn", zapcore.WarnLevel},
		{"error", "error", zapcore.ErrorLevel},
		{"fatal", "fatal", zapcore.FatalLevel},
		{"invalid", "invalid", zapcore.InfoLevel},
		{"empty", "", zapcore.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetLevel(tt.levelStr)
			if atomicLevel.Level() != tt.expected {
				t.Errorf("Expected level %v, got %v", tt.expected, atomicLevel.Level())
			}
		})
	}
}

func TestLogFunctions(t *testing.T) {
	SetLevel("debug")

	Debug("test debug message", zap.String("key", "value"))
	Info("test info message", zap.String("key", "value"))
	Warn("test warn message", zap.String("key", "value"))
	Error("test error message", zap.String("key", "value"))
}


func TestSync(t *testing.T) {
	Sync()
}

func TestParseLogLevel(t *testing.T) {
	key := "PODTRACE_LOG_LEVEL"
	originalValue := os.Getenv(key)
	defer func() {
		if originalValue != "" {
			_ = os.Setenv(key, originalValue)
		} else {
			_ = os.Unsetenv(key)
		}
	}()

	tests := []struct {
		name     string
		levelStr string
		expected zapcore.Level
	}{
		{"debug", "debug", zapcore.DebugLevel},
		{"info", "info", zapcore.InfoLevel},
		{"warn", "warn", zapcore.WarnLevel},
		{"error", "error", zapcore.ErrorLevel},
		{"fatal", "fatal", zapcore.FatalLevel},
		{"invalid", "invalid", zapcore.InfoLevel},
		{"uppercase", "DEBUG", zapcore.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLogLevel(tt.levelStr)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}


