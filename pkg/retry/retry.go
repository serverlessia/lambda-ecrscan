package retry

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"ecr-image-scanner/pkg/errors"
)

// Config holds retry configuration
type Config struct {
	MaxAttempts     int           `json:"maxAttempts"`
	InitialDelay    time.Duration `json:"initialDelay"`
	MaxDelay        time.Duration `json:"maxDelay"`
	BackoffFactor   float64       `json:"backoffFactor"`
	Jitter          bool          `json:"jitter"`
	RetryableErrors []errors.ErrorType `json:"retryableErrors"`
}

// DefaultConfig returns a default retry configuration
func DefaultConfig() *Config {
	return &Config{
		MaxAttempts:   3,
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      30 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        true,
		RetryableErrors: []errors.ErrorType{
			errors.ErrorTypeNetwork,
			errors.ErrorTypeResource,
		},
	}
}

// NetworkConfig returns retry configuration optimized for network operations
func NetworkConfig() *Config {
	return &Config{
		MaxAttempts:   5,
		InitialDelay:  200 * time.Millisecond,
		MaxDelay:      60 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        true,
		RetryableErrors: []errors.ErrorType{
			errors.ErrorTypeNetwork,
		},
	}
}

// DatabaseConfig returns retry configuration optimized for database operations
func DatabaseConfig() *Config {
	return &Config{
		MaxAttempts:   3,
		InitialDelay:  500 * time.Millisecond,
		MaxDelay:      10 * time.Second,
		BackoffFactor: 1.5,
		Jitter:        true,
		RetryableErrors: []errors.ErrorType{
			errors.ErrorTypeDatabase,
		},
	}
}

// Retrier handles retry logic with exponential backoff
type Retrier struct {
	config *Config
}

// New creates a new Retrier with the given configuration
func New(config *Config) *Retrier {
	if config == nil {
		config = DefaultConfig()
	}
	return &Retrier{config: config}
}

// RetryFunc represents a function that can be retried
type RetryFunc func() error

// RetryWithContextFunc represents a function with context that can be retried
type RetryWithContextFunc func(ctx context.Context) error

// Execute executes a function with retry logic
func (r *Retrier) Execute(fn RetryFunc) error {
	return r.ExecuteWithContext(context.Background(), func(ctx context.Context) error {
		return fn()
	})
}

// ExecuteWithContext executes a function with context and retry logic
func (r *Retrier) ExecuteWithContext(ctx context.Context, fn RetryWithContextFunc) error {
	var lastErr error
	
	for attempt := 1; attempt <= r.config.MaxAttempts; attempt++ {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Execute the function
		err := fn(ctx)
		if err == nil {
			return nil // Success
		}

		lastErr = err

		// Check if this is the last attempt
		if attempt == r.config.MaxAttempts {
			break
		}

		// Check if the error is retryable
		if !r.isRetryable(err) {
			return err // Don't retry non-retryable errors
		}

		// Calculate delay for next attempt
		delay := r.calculateDelay(attempt)
		
		// Add error context for retry attempt
		if scannerErr, ok := err.(*errors.ScannerError); ok {
			scannerErr.WithDetail("retry_attempt", fmt.Sprintf("%d", attempt)).
				WithDetail("next_retry_delay_ms", fmt.Sprintf("%.0f", delay.Seconds()*1000))
		}

		// Wait before next attempt
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	// All attempts failed, return the last error with retry context
	if scannerErr, ok := lastErr.(*errors.ScannerError); ok {
		scannerErr.WithDetail("total_attempts", fmt.Sprintf("%d", r.config.MaxAttempts)).
			WithDetail("retry_exhausted", "true")
	}

	return lastErr
}

// isRetryable checks if an error should be retried
func (r *Retrier) isRetryable(err error) bool {
	// Check if it's a ScannerError and explicitly marked as retryable
	if scannerErr, ok := err.(*errors.ScannerError); ok {
		if !scannerErr.IsRetryable() {
			return false
		}
		
		// Check if the error type is in our retryable list
		for _, retryableType := range r.config.RetryableErrors {
			if scannerErr.Type == retryableType {
				return true
			}
		}
		return false
	}

	// For non-ScannerError types, use heuristics
	return errors.IsTemporaryError(err)
}

// calculateDelay calculates the delay for the next retry attempt
func (r *Retrier) calculateDelay(attempt int) time.Duration {
	// Calculate exponential backoff delay
	delay := float64(r.config.InitialDelay) * math.Pow(r.config.BackoffFactor, float64(attempt-1))
	
	// Apply maximum delay limit
	if delay > float64(r.config.MaxDelay) {
		delay = float64(r.config.MaxDelay)
	}

	// Add jitter if enabled
	if r.config.Jitter {
		// Add random jitter up to 25% of the delay
		jitterRange := delay * 0.25
		jitter := rand.Float64() * jitterRange
		delay += jitter
	}

	return time.Duration(delay)
}

// WithMaxAttempts creates a new retrier with modified max attempts
func (r *Retrier) WithMaxAttempts(maxAttempts int) *Retrier {
	newConfig := *r.config
	newConfig.MaxAttempts = maxAttempts
	return &Retrier{config: &newConfig}
}

// WithInitialDelay creates a new retrier with modified initial delay
func (r *Retrier) WithInitialDelay(delay time.Duration) *Retrier {
	newConfig := *r.config
	newConfig.InitialDelay = delay
	return &Retrier{config: &newConfig}
}

// WithMaxDelay creates a new retrier with modified max delay
func (r *Retrier) WithMaxDelay(delay time.Duration) *Retrier {
	newConfig := *r.config
	newConfig.MaxDelay = delay
	return &Retrier{config: &newConfig}
}

// RetryableOperation represents an operation that can be retried with specific configuration
type RetryableOperation struct {
	Name        string
	Operation   RetryWithContextFunc
	Config      *Config
	OnRetry     func(attempt int, err error) // Optional callback for retry events
	OnSuccess   func(attempts int)           // Optional callback for success
	OnFailure   func(attempts int, err error) // Optional callback for final failure
}

// Execute executes a retryable operation
func (op *RetryableOperation) Execute(ctx context.Context) error {
	retrier := New(op.Config)
	var attempts int
	
	err := retrier.ExecuteWithContext(ctx, func(ctx context.Context) error {
		attempts++
		err := op.Operation(ctx)
		
		if err != nil && op.OnRetry != nil && attempts < retrier.config.MaxAttempts {
			op.OnRetry(attempts, err)
		}
		
		return err
	})

	if err != nil && op.OnFailure != nil {
		op.OnFailure(attempts, err)
	} else if err == nil && op.OnSuccess != nil {
		op.OnSuccess(attempts)
	}

	return err
}

// Common retry operations

// RetryECROperation retries ECR-specific operations with appropriate configuration
func RetryECROperation(ctx context.Context, operation RetryWithContextFunc) error {
	config := NetworkConfig()
	config.RetryableErrors = append(config.RetryableErrors, errors.ErrorTypeAuth)
	
	retrier := New(config)
	return retrier.ExecuteWithContext(ctx, operation)
}

// RetryLayerDownload retries layer download operations with extended timeout
func RetryLayerDownload(ctx context.Context, operation RetryWithContextFunc) error {
	config := NetworkConfig()
	config.MaxAttempts = 3
	config.MaxDelay = 2 * time.Minute // Longer delay for large layer downloads
	
	retrier := New(config)
	return retrier.ExecuteWithContext(ctx, operation)
}

// RetryDatabaseOperation retries database operations with appropriate configuration
func RetryDatabaseOperation(ctx context.Context, operation RetryWithContextFunc) error {
	retrier := New(DatabaseConfig())
	return retrier.ExecuteWithContext(ctx, operation)
}

// RetryWithCircuitBreaker implements a simple circuit breaker pattern
type CircuitBreaker struct {
	maxFailures     int
	resetTimeout    time.Duration
	failures        int
	lastFailureTime time.Time
	state           CircuitState
}

type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        CircuitClosed,
	}
}

// Execute executes an operation with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, operation RetryWithContextFunc) error {
	// Check circuit state
	if cb.state == CircuitOpen {
		if time.Since(cb.lastFailureTime) > cb.resetTimeout {
			cb.state = CircuitHalfOpen
		} else {
			return errors.NewResourceError("CIRCUIT_BREAKER_OPEN", 
				"Circuit breaker is open, operation not attempted", nil).
				WithDetail("failures", fmt.Sprintf("%d", cb.failures)).
				WithDetail("max_failures", fmt.Sprintf("%d", cb.maxFailures))
		}
	}

	// Execute operation
	err := operation(ctx)
	
	if err != nil {
		cb.failures++
		cb.lastFailureTime = time.Now()
		
		if cb.failures >= cb.maxFailures {
			cb.state = CircuitOpen
		}
		
		return err
	}

	// Success - reset circuit breaker
	cb.failures = 0
	cb.state = CircuitClosed
	return nil
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() CircuitState {
	return cb.state
}

// Reset manually resets the circuit breaker
func (cb *CircuitBreaker) Reset() {
	cb.failures = 0
	cb.state = CircuitClosed
}