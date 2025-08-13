package retry

import (
	"context"
	"fmt"
	"testing"
	"time"

	"ecr-image-scanner/pkg/errors"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.MaxAttempts != 3 {
		t.Errorf("Expected MaxAttempts=3, got %d", config.MaxAttempts)
	}
	if config.InitialDelay != 100*time.Millisecond {
		t.Errorf("Expected InitialDelay=100ms, got %v", config.InitialDelay)
	}
	if config.MaxDelay != 30*time.Second {
		t.Errorf("Expected MaxDelay=30s, got %v", config.MaxDelay)
	}
	if config.BackoffFactor != 2.0 {
		t.Errorf("Expected BackoffFactor=2.0, got %f", config.BackoffFactor)
	}
	if !config.Jitter {
		t.Error("Expected Jitter=true")
	}
}

func TestNetworkConfig(t *testing.T) {
	config := NetworkConfig()

	if config.MaxAttempts != 5 {
		t.Errorf("Expected MaxAttempts=5, got %d", config.MaxAttempts)
	}
	if config.InitialDelay != 200*time.Millisecond {
		t.Errorf("Expected InitialDelay=200ms, got %v", config.InitialDelay)
	}
	if config.MaxDelay != 60*time.Second {
		t.Errorf("Expected MaxDelay=60s, got %v", config.MaxDelay)
	}
}

func TestDatabaseConfig(t *testing.T) {
	config := DatabaseConfig()

	if config.MaxAttempts != 3 {
		t.Errorf("Expected MaxAttempts=3, got %d", config.MaxAttempts)
	}
	if config.InitialDelay != 500*time.Millisecond {
		t.Errorf("Expected InitialDelay=500ms, got %v", config.InitialDelay)
	}
	if config.BackoffFactor != 1.5 {
		t.Errorf("Expected BackoffFactor=1.5, got %f", config.BackoffFactor)
	}
}

func TestRetrier_Execute_Success(t *testing.T) {
	retrier := New(DefaultConfig())
	callCount := 0

	err := retrier.Execute(func() error {
		callCount++
		return nil // Success on first try
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("Expected 1 call, got %d", callCount)
	}
}

func TestRetrier_Execute_SuccessAfterRetries(t *testing.T) {
	config := DefaultConfig()
	config.InitialDelay = 1 * time.Millisecond // Speed up test
	config.Jitter = false                      // Disable jitter for predictable timing
	retrier := New(config)
	callCount := 0

	err := retrier.Execute(func() error {
		callCount++
		if callCount < 3 {
			return errors.NewNetworkError("TEST_ERROR", "Test error", nil, true)
		}
		return nil // Success on third try
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if callCount != 3 {
		t.Errorf("Expected 3 calls, got %d", callCount)
	}
}

func TestRetrier_Execute_MaxAttemptsExceeded(t *testing.T) {
	config := DefaultConfig()
	config.InitialDelay = 1 * time.Millisecond // Speed up test
	config.Jitter = false                      // Disable jitter for predictable timing
	retrier := New(config)
	callCount := 0

	err := retrier.Execute(func() error {
		callCount++
		return errors.NewNetworkError("TEST_ERROR", "Test error", nil, true)
	})

	if err == nil {
		t.Error("Expected error after max attempts exceeded")
	}
	if callCount != config.MaxAttempts {
		t.Errorf("Expected %d calls, got %d", config.MaxAttempts, callCount)
	}

	// Check that error has retry context
	if scannerErr, ok := err.(*errors.ScannerError); ok {
		if scannerErr.Details["total_attempts"] != "3" {
			t.Errorf("Expected total_attempts=3, got %s", scannerErr.Details["total_attempts"])
		}
		if scannerErr.Details["retry_exhausted"] != "true" {
			t.Errorf("Expected retry_exhausted=true, got %s", scannerErr.Details["retry_exhausted"])
		}
	} else {
		t.Error("Expected ScannerError with retry context")
	}
}

func TestRetrier_Execute_NonRetryableError(t *testing.T) {
	retrier := New(DefaultConfig())
	callCount := 0

	err := retrier.Execute(func() error {
		callCount++
		return errors.NewAuthError("AUTH_FAILED", "Authentication failed", nil)
	})

	if err == nil {
		t.Error("Expected error")
	}
	if callCount != 1 {
		t.Errorf("Expected 1 call (no retries), got %d", callCount)
	}
}

func TestRetrier_ExecuteWithContext_ContextCancelled(t *testing.T) {
	retrier := New(DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	callCount := 0

	// Cancel context after first call
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := retrier.ExecuteWithContext(ctx, func(ctx context.Context) error {
		callCount++
		if callCount == 1 {
			time.Sleep(20 * time.Millisecond) // Ensure context gets cancelled
		}
		return errors.NewNetworkError("TEST_ERROR", "Test error", nil, true)
	})

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got %v", err)
	}
}

func TestRetrier_isRetryable(t *testing.T) {
	config := DefaultConfig()
	config.RetryableErrors = []errors.ErrorType{errors.ErrorTypeNetwork}
	retrier := New(config)

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "retryable network error",
			err:      errors.NewNetworkError("TEST", "Test", nil, true),
			expected: true,
		},
		{
			name:     "non-retryable network error",
			err:      errors.NewNetworkError("TEST", "Test", nil, false),
			expected: false,
		},
		{
			name:     "retryable auth error not in config",
			err:      errors.NewAuthError("TEST", "Test", nil),
			expected: false,
		},
		{
			name:     "regular error",
			err:      fmt.Errorf("regular error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := retrier.isRetryable(tt.err); got != tt.expected {
				t.Errorf("isRetryable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestRetrier_calculateDelay(t *testing.T) {
	config := &Config{
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      1 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        false,
	}
	retrier := New(config)

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{5, 1 * time.Second}, // Capped at MaxDelay
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
			delay := retrier.calculateDelay(tt.attempt)
			if delay != tt.expected {
				t.Errorf("calculateDelay(%d) = %v, want %v", tt.attempt, delay, tt.expected)
			}
		})
	}
}

func TestRetrier_calculateDelay_WithJitter(t *testing.T) {
	config := &Config{
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      1 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        true,
	}
	retrier := New(config)

	// With jitter, delay should be within expected range
	delay := retrier.calculateDelay(1)
	expectedMin := 100 * time.Millisecond
	expectedMax := 125 * time.Millisecond // 100ms + 25% jitter

	if delay < expectedMin || delay > expectedMax {
		t.Errorf("calculateDelay(1) with jitter = %v, expected between %v and %v", delay, expectedMin, expectedMax)
	}
}

func TestRetrier_WithMethods(t *testing.T) {
	original := New(DefaultConfig())

	t.Run("WithMaxAttempts", func(t *testing.T) {
		modified := original.WithMaxAttempts(5)
		if modified.config.MaxAttempts != 5 {
			t.Errorf("Expected MaxAttempts=5, got %d", modified.config.MaxAttempts)
		}
		// Original should be unchanged
		if original.config.MaxAttempts != 3 {
			t.Errorf("Original MaxAttempts should be unchanged, got %d", original.config.MaxAttempts)
		}
	})

	t.Run("WithInitialDelay", func(t *testing.T) {
		newDelay := 500 * time.Millisecond
		modified := original.WithInitialDelay(newDelay)
		if modified.config.InitialDelay != newDelay {
			t.Errorf("Expected InitialDelay=%v, got %v", newDelay, modified.config.InitialDelay)
		}
	})

	t.Run("WithMaxDelay", func(t *testing.T) {
		newMaxDelay := 2 * time.Minute
		modified := original.WithMaxDelay(newMaxDelay)
		if modified.config.MaxDelay != newMaxDelay {
			t.Errorf("Expected MaxDelay=%v, got %v", newMaxDelay, modified.config.MaxDelay)
		}
	})
}

func TestRetryableOperation_Execute(t *testing.T) {
	callCount := 0
	retryCount := 0
	successCount := 0
	failureCount := 0

	operation := &RetryableOperation{
		Name: "test_operation",
		Operation: func(ctx context.Context) error {
			callCount++
			if callCount < 3 {
				return errors.NewNetworkError("TEST", "Test error", nil, true)
			}
			return nil
		},
		Config: &Config{
			MaxAttempts:   3,
			InitialDelay:  1 * time.Millisecond,
			MaxDelay:      10 * time.Millisecond,
			BackoffFactor: 2.0,
			Jitter:        false,
			RetryableErrors: []errors.ErrorType{errors.ErrorTypeNetwork},
		},
		OnRetry: func(attempt int, err error) {
			retryCount++
		},
		OnSuccess: func(attempts int) {
			successCount++
		},
		OnFailure: func(attempts int, err error) {
			failureCount++
		},
	}

	err := operation.Execute(context.Background())

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if callCount != 3 {
		t.Errorf("Expected 3 calls, got %d", callCount)
	}
	if retryCount != 2 {
		t.Errorf("Expected 2 retries, got %d", retryCount)
	}
	if successCount != 1 {
		t.Errorf("Expected 1 success callback, got %d", successCount)
	}
	if failureCount != 0 {
		t.Errorf("Expected 0 failure callbacks, got %d", failureCount)
	}
}

func TestRetryECROperation(t *testing.T) {
	callCount := 0

	err := RetryECROperation(context.Background(), func(ctx context.Context) error {
		callCount++
		if callCount == 1 {
			return errors.NewECRConnectionError(fmt.Errorf("connection failed"))
		}
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if callCount != 2 {
		t.Errorf("Expected 2 calls, got %d", callCount)
	}
}

func TestRetryLayerDownload(t *testing.T) {
	callCount := 0

	err := RetryLayerDownload(context.Background(), func(ctx context.Context) error {
		callCount++
		if callCount == 1 {
			return errors.NewLayerDownloadError("sha256:abc", fmt.Errorf("download failed"))
		}
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if callCount != 2 {
		t.Errorf("Expected 2 calls, got %d", callCount)
	}
}

func TestRetryDatabaseOperation(t *testing.T) {
	callCount := 0

	err := RetryDatabaseOperation(context.Background(), func(ctx context.Context) error {
		callCount++
		if callCount == 1 {
			return errors.NewDatabaseInitError(fmt.Errorf("init failed"))
		}
		return nil
	})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if callCount != 2 {
		t.Errorf("Expected 2 calls, got %d", callCount)
	}
}

func TestCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker(2, 100*time.Millisecond)

	t.Run("InitialState", func(t *testing.T) {
		if cb.GetState() != CircuitClosed {
			t.Errorf("Expected initial state to be CircuitClosed, got %v", cb.GetState())
		}
	})

	t.Run("FailuresOpenCircuit", func(t *testing.T) {
		// First failure
		err1 := cb.Execute(context.Background(), func(ctx context.Context) error {
			return fmt.Errorf("failure 1")
		})
		if err1 == nil {
			t.Error("Expected error from first failure")
		}
		if cb.GetState() != CircuitClosed {
			t.Errorf("Expected state to remain CircuitClosed after first failure, got %v", cb.GetState())
		}

		// Second failure - should open circuit
		err2 := cb.Execute(context.Background(), func(ctx context.Context) error {
			return fmt.Errorf("failure 2")
		})
		if err2 == nil {
			t.Error("Expected error from second failure")
		}
		if cb.GetState() != CircuitOpen {
			t.Errorf("Expected state to be CircuitOpen after max failures, got %v", cb.GetState())
		}
	})

	t.Run("OpenCircuitRejectsRequests", func(t *testing.T) {
		err := cb.Execute(context.Background(), func(ctx context.Context) error {
			t.Error("Operation should not be called when circuit is open")
			return nil
		})

		if err == nil {
			t.Error("Expected error when circuit is open")
		}
		if scannerErr, ok := err.(*errors.ScannerError); ok {
			if scannerErr.Code != "CIRCUIT_BREAKER_OPEN" {
				t.Errorf("Expected CIRCUIT_BREAKER_OPEN error, got %s", scannerErr.Code)
			}
		} else {
			t.Error("Expected ScannerError for circuit breaker open")
		}
	})

	t.Run("CircuitResetAfterTimeout", func(t *testing.T) {
		// Wait for reset timeout
		time.Sleep(150 * time.Millisecond)

		// Should transition to half-open and allow one request
		callCount := 0
		err := cb.Execute(context.Background(), func(ctx context.Context) error {
			callCount++
			return nil // Success
		})

		if err != nil {
			t.Errorf("Expected no error after reset timeout, got %v", err)
		}
		if callCount != 1 {
			t.Errorf("Expected 1 call after reset, got %d", callCount)
		}
		if cb.GetState() != CircuitClosed {
			t.Errorf("Expected state to be CircuitClosed after successful call, got %v", cb.GetState())
		}
	})

	t.Run("Reset", func(t *testing.T) {
		// Force some failures to open circuit
		cb.Execute(context.Background(), func(ctx context.Context) error {
			return fmt.Errorf("failure")
		})
		cb.Execute(context.Background(), func(ctx context.Context) error {
			return fmt.Errorf("failure")
		})

		if cb.GetState() != CircuitOpen {
			t.Error("Circuit should be open before reset")
		}

		cb.Reset()

		if cb.GetState() != CircuitClosed {
			t.Errorf("Expected state to be CircuitClosed after reset, got %v", cb.GetState())
		}
	})
}