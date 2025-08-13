package integration

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"ecr-image-scanner/internal/handler"
	"ecr-image-scanner/pkg/analyzer"
	"ecr-image-scanner/pkg/scanner"
	"ecr-image-scanner/pkg/types"
	"ecr-image-scanner/pkg/vulndb"
	"ecr-image-scanner/test/fixtures"
)

// PerformanceMetrics holds performance measurement data
type PerformanceMetrics struct {
	Duration       time.Duration
	MemoryUsed     uint64
	MemoryPeak     uint64
	GoroutineCount int
	Vulnerabilities int
	LayersProcessed int
	PackagesFound   int
}

// TestScannerPerformanceWithDifferentImageSizes tests performance across various image sizes
func TestScannerPerformanceWithDifferentImageSizes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	testCases := []struct {
		name           string
		imageType      string
		expectedMaxDuration time.Duration
		expectedMaxMemory   uint64 // in MB
	}{
		{
			name:           "small image performance",
			imageType:      "small",
			expectedMaxDuration: 5 * time.Second,
			expectedMaxMemory:   50 * 1024 * 1024, // 50MB
		},
		{
			name:           "medium image performance",
			imageType:      "medium",
			expectedMaxDuration: 15 * time.Second,
			expectedMaxMemory:   100 * 1024 * 1024, // 100MB
		},
		{
			name:           "large image performance",
			imageType:      "large",
			expectedMaxDuration: 30 * time.Second,
			expectedMaxMemory:   200 * 1024 * 1024, // 200MB
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test components
			vulnDB := vulndb.NewVulnDB()
			layerAnalyzer := analyzer.NewLayerAnalyzer(1024 * 1024) // 1MB max layer size
			scannerImpl := scanner.NewVulnerabilityScanner(vulnDB, layerAnalyzer)

			ctx := context.Background()
			err := scannerImpl.LoadVulnerabilityDatabase(ctx)
			if err != nil {
				t.Fatalf("Failed to load vulnerability database: %v", err)
			}

			// Get test data
			manifest := fixtures.TestImageManifests[tc.imageType]
			layers := fixtures.TestImageLayers[tc.imageType]

			// Measure performance
			metrics := measurePerformance(t, func() error {
				_, err := scannerImpl.ScanImage(ctx, manifest, layers, types.ScanModeBasic)
				return err
			})

			// Validate performance requirements
			if metrics.Duration > tc.expectedMaxDuration {
				t.Errorf("Scan took too long: %v (max: %v)", metrics.Duration, tc.expectedMaxDuration)
			}

			if metrics.MemoryUsed > tc.expectedMaxMemory {
				t.Errorf("Memory usage too high: %d bytes (max: %d bytes)", 
					metrics.MemoryUsed, tc.expectedMaxMemory)
			}

			// Log performance metrics
			t.Logf("Performance metrics for %s:", tc.name)
			t.Logf("  Duration: %v", metrics.Duration)
			t.Logf("  Memory used: %.2f MB", float64(metrics.MemoryUsed)/(1024*1024))
			t.Logf("  Memory peak: %.2f MB", float64(metrics.MemoryPeak)/(1024*1024))
			t.Logf("  Goroutines: %d", metrics.GoroutineCount)
			t.Logf("  Vulnerabilities found: %d", metrics.Vulnerabilities)
		})
	}
}

// TestScannerPerformanceBasicVsEnhanced compares performance between scan modes
func TestScannerPerformanceBasicVsEnhanced(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	// Create test components
	vulnDB := vulndb.NewVulnDB()
	layerAnalyzer := analyzer.NewLayerAnalyzer(1024 * 1024) // 1MB max layer size
	scannerImpl := scanner.NewVulnerabilityScanner(vulnDB, layerAnalyzer)

	ctx := context.Background()
	err := scannerImpl.LoadVulnerabilityDatabase(ctx)
	if err != nil {
		t.Fatalf("Failed to load vulnerability database: %v", err)
	}

	manifest := fixtures.TestImageManifests["medium"]
	layers := fixtures.TestImageLayers["medium"]

	// Test basic mode
	basicMetrics := measurePerformance(t, func() error {
		_, err := scannerImpl.ScanImage(ctx, manifest, layers, types.ScanModeBasic)
		return err
	})

	// Test enhanced mode
	enhancedMetrics := measurePerformance(t, func() error {
		_, err := scannerImpl.ScanImage(ctx, manifest, layers, types.ScanModeEnhanced)
		return err
	})

	// Compare performance
	t.Logf("Basic mode performance:")
	t.Logf("  Duration: %v", basicMetrics.Duration)
	t.Logf("  Memory: %.2f MB", float64(basicMetrics.MemoryUsed)/(1024*1024))
	t.Logf("  Vulnerabilities: %d", basicMetrics.Vulnerabilities)

	t.Logf("Enhanced mode performance:")
	t.Logf("  Duration: %v", enhancedMetrics.Duration)
	t.Logf("  Memory: %.2f MB", float64(enhancedMetrics.MemoryUsed)/(1024*1024))
	t.Logf("  Vulnerabilities: %d", enhancedMetrics.Vulnerabilities)

	// Enhanced mode should not be more than 2x slower than basic mode
	if enhancedMetrics.Duration > basicMetrics.Duration*2 {
		t.Errorf("Enhanced mode too slow compared to basic: %v vs %v", 
			enhancedMetrics.Duration, basicMetrics.Duration)
	}

	// Enhanced mode should find at least as many vulnerabilities as basic mode
	if enhancedMetrics.Vulnerabilities < basicMetrics.Vulnerabilities {
		t.Errorf("Enhanced mode found fewer vulnerabilities than basic: %d vs %d",
			enhancedMetrics.Vulnerabilities, basicMetrics.Vulnerabilities)
	}
}

// TestHandlerPerformanceWithConfiguration tests handler performance with different configurations
func TestHandlerPerformanceWithConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	testCases := []struct {
		name   string
		event  types.LambdaEvent
		config *handler.Config
	}{
		{
			name: "default configuration",
			event: types.LambdaEvent{
				ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:      "latest",
				ScanMode: "basic",
			},
			config: &handler.Config{},
		},
		{
			name: "with severity filter",
			event: types.LambdaEvent{
				ImageURL:       "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:            "latest",
				ScanMode:       "enhanced",
				SeverityFilter: "HIGH",
			},
			config: &handler.Config{},
		},
		{
			name: "with max findings limit",
			event: types.LambdaEvent{
				ImageURL:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:         "latest",
				ScanMode:    "enhanced",
				MaxFindings: 10,
			},
			config: &handler.Config{},
		},
		{
			name: "with caching disabled",
			event: types.LambdaEvent{
				ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:      "latest",
				ScanMode: "basic",
			},
			config: &handler.Config{
				CacheEnabled: false,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := handler.NewWithConfig(tc.config)
			
			metrics := measurePerformance(t, func() error {
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
				defer cancel()
				
				_, err := h.Handle(ctx, tc.event)
				return err
			})

			// Log performance metrics
			t.Logf("Handler performance for %s:", tc.name)
			t.Logf("  Duration: %v", metrics.Duration)
			t.Logf("  Memory used: %.2f MB", float64(metrics.MemoryUsed)/(1024*1024))
			t.Logf("  Goroutines: %d", metrics.GoroutineCount)

			// Basic performance requirements
			maxDuration := 30 * time.Second
			maxMemory := uint64(150 * 1024 * 1024) // 150MB

			if metrics.Duration > maxDuration {
				t.Errorf("Handler took too long: %v (max: %v)", metrics.Duration, maxDuration)
			}

			if metrics.MemoryUsed > maxMemory {
				t.Errorf("Handler used too much memory: %d bytes (max: %d bytes)", 
					metrics.MemoryUsed, maxMemory)
			}
		})
	}
}

// TestConcurrentScanPerformance tests performance under concurrent load
func TestConcurrentScanPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent performance test in short mode")
	}

	const numConcurrentScans = 5
	const maxDurationPerScan = 45 * time.Second

	event := types.LambdaEvent{
		ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
		Tag:      "latest",
		ScanMode: "basic",
	}

	h := handler.New()

	// Channel to collect metrics
	results := make(chan PerformanceMetrics, numConcurrentScans)

	startTime := time.Now()

	// Start concurrent scans
	for i := 0; i < numConcurrentScans; i++ {
		go func(scanID int) {
			metrics := measurePerformance(t, func() error {
				ctx, cancel := context.WithTimeout(context.Background(), maxDurationPerScan)
				defer cancel()
				
				_, err := h.Handle(ctx, event)
				return err
			})
			results <- metrics
		}(i)
	}

	// Collect results
	var totalDuration time.Duration
	var maxDuration time.Duration
	var totalMemory uint64

	for i := 0; i < numConcurrentScans; i++ {
		metrics := <-results
		totalDuration += metrics.Duration
		if metrics.Duration > maxDuration {
			maxDuration = metrics.Duration
		}
		totalMemory += metrics.MemoryUsed

		t.Logf("Concurrent scan %d: %v, %.2f MB", 
			i, metrics.Duration, float64(metrics.MemoryUsed)/(1024*1024))
	}

	overallDuration := time.Since(startTime)
	avgDuration := totalDuration / numConcurrentScans
	avgMemory := totalMemory / numConcurrentScans

	t.Logf("Concurrent performance summary:")
	t.Logf("  Overall duration: %v", overallDuration)
	t.Logf("  Average scan duration: %v", avgDuration)
	t.Logf("  Maximum scan duration: %v", maxDuration)
	t.Logf("  Average memory per scan: %.2f MB", float64(avgMemory)/(1024*1024))

	// Validate concurrent performance
	if maxDuration > maxDurationPerScan {
		t.Errorf("Concurrent scan took too long: %v (max: %v)", maxDuration, maxDurationPerScan)
	}

	// Overall duration should be much less than sum of individual durations
	if overallDuration > totalDuration/2 {
		t.Errorf("Concurrent execution not efficient: %v vs %v sequential", 
			overallDuration, totalDuration)
	}
}

// TestMemoryLeakDetection tests for memory leaks during repeated scans
func TestMemoryLeakDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak test in short mode")
	}

	const numIterations = 10
	const memoryGrowthThreshold = 50 * 1024 * 1024 // 50MB

	event := types.LambdaEvent{
		ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
		Tag:      "latest",
		ScanMode: "basic",
	}

	h := handler.New()

	var memoryUsages []uint64

	for i := 0; i < numIterations; i++ {
		// Force garbage collection before measurement
		runtime.GC()
		runtime.GC() // Call twice to ensure cleanup

		var beforeStats runtime.MemStats
		runtime.ReadMemStats(&beforeStats)

		// Perform scan
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := h.Handle(ctx, event)
		cancel()

		if err != nil {
			t.Fatalf("Scan %d failed: %v", i, err)
		}

		// Force garbage collection after scan
		runtime.GC()
		runtime.GC()

		var afterStats runtime.MemStats
		runtime.ReadMemStats(&afterStats)

		memoryUsed := afterStats.Alloc - beforeStats.Alloc
		memoryUsages = append(memoryUsages, memoryUsed)

		t.Logf("Iteration %d: Memory used: %.2f MB", i, float64(memoryUsed)/(1024*1024))
	}

	// Check for memory growth trend
	if len(memoryUsages) >= 3 {
		firstThird := average(memoryUsages[:len(memoryUsages)/3])
		lastThird := average(memoryUsages[len(memoryUsages)*2/3:])

		memoryGrowth := int64(lastThird) - int64(firstThird)
		
		t.Logf("Memory growth analysis:")
		t.Logf("  First third average: %.2f MB", float64(firstThird)/(1024*1024))
		t.Logf("  Last third average: %.2f MB", float64(lastThird)/(1024*1024))
		t.Logf("  Growth: %.2f MB", float64(memoryGrowth)/(1024*1024))

		if memoryGrowth > int64(memoryGrowthThreshold) {
			t.Errorf("Potential memory leak detected: growth of %.2f MB", 
				float64(memoryGrowth)/(1024*1024))
		}
	}
}

// TestLargeImageHandling tests performance with simulated large images
func TestLargeImageHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large image test in short mode")
	}

	// Create a simulated large image with many layers
	largeManifest := &types.ImageManifest{
		MediaType: "application/vnd.docker.distribution.manifest.v2+json",
		Digest:    "sha256:large-simulated-image",
		Layers:    make([]types.LayerDigest, 20), // 20 layers
	}

	largeLayers := make([]types.ImageLayer, 20)
	
	// Create layers with varying sizes
	for i := 0; i < 20; i++ {
		layerSize := int64(10240 * (i + 1)) // Increasing layer sizes
		largeManifest.Layers[i] = types.LayerDigest{
			Digest:    fmt.Sprintf("sha256:layer%d-large", i),
			MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
			Size:      layerSize,
		}
		
		largeLayers[i] = types.ImageLayer{
			Digest:  fmt.Sprintf("sha256:layer%d-large", i),
			Content: generateTestContent(layerSize),
			Size:    layerSize,
		}
	}

	// Test with large image
	vulnDB := vulndb.NewVulnDB()
	layerAnalyzer := analyzer.NewLayerAnalyzer(1024 * 1024) // 1MB max layer size
	scannerImpl := scanner.NewVulnerabilityScanner(vulnDB, layerAnalyzer)

	ctx := context.Background()
	err := scannerImpl.LoadVulnerabilityDatabase(ctx)
	if err != nil {
		t.Fatalf("Failed to load vulnerability database: %v", err)
	}

	metrics := measurePerformance(t, func() error {
		_, err := scannerImpl.ScanImage(ctx, largeManifest, largeLayers, types.ScanModeBasic)
		return err
	})

	// Performance requirements for large images
	maxDuration := 2 * time.Minute
	maxMemory := uint64(500 * 1024 * 1024) // 500MB

	if metrics.Duration > maxDuration {
		t.Errorf("Large image scan took too long: %v (max: %v)", metrics.Duration, maxDuration)
	}

	if metrics.MemoryUsed > maxMemory {
		t.Errorf("Large image scan used too much memory: %d bytes (max: %d bytes)", 
			metrics.MemoryUsed, maxMemory)
	}

	t.Logf("Large image performance:")
	t.Logf("  Duration: %v", metrics.Duration)
	t.Logf("  Memory used: %.2f MB", float64(metrics.MemoryUsed)/(1024*1024))
	t.Logf("  Layers processed: %d", len(largeLayers))
}

// measurePerformance measures performance metrics for a given function
func measurePerformance(t *testing.T, fn func() error) PerformanceMetrics {
	t.Helper()

	// Force garbage collection before measurement
	runtime.GC()
	runtime.GC()

	var beforeStats runtime.MemStats
	runtime.ReadMemStats(&beforeStats)
	
	beforeGoroutines := runtime.NumGoroutine()
	startTime := time.Now()

	// Execute function
	err := fn()
	if err != nil {
		t.Fatalf("Performance test function failed: %v", err)
	}

	duration := time.Since(startTime)

	// Force garbage collection after execution
	runtime.GC()
	runtime.GC()

	var afterStats runtime.MemStats
	runtime.ReadMemStats(&afterStats)
	
	afterGoroutines := runtime.NumGoroutine()

	return PerformanceMetrics{
		Duration:       duration,
		MemoryUsed:     afterStats.TotalAlloc - beforeStats.TotalAlloc,
		MemoryPeak:     afterStats.Sys,
		GoroutineCount: afterGoroutines - beforeGoroutines,
	}
}

// generateTestContent creates test content of specified size
func generateTestContent(size int64) []byte {
	content := make([]byte, size)
	pattern := []byte("test content pattern ")
	patternLen := int64(len(pattern))
	
	for i := int64(0); i < size; i++ {
		content[i] = pattern[i%patternLen]
	}
	
	return content
}

// average calculates the average of a slice of uint64 values
func average(values []uint64) uint64 {
	if len(values) == 0 {
		return 0
	}
	
	var sum uint64
	for _, v := range values {
		sum += v
	}
	
	return sum / uint64(len(values))
}