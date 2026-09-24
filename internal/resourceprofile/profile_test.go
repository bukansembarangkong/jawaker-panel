package resourceprofile

import (
	"testing"
)

func TestClassifyProfiles(t *testing.T) {
	tests := []struct {
		name       string
		cpus       int
		ramMB      int
		wantTier   ProfileName
		wantWorker int
	}{
		{"tiny single core 1GB", 1, 1024, ProfileTiny, 1},
		{"small dual core 2GB", 2, 2048, ProfileSmall, 2},
		{"medium quad core 8GB", 4, 8192, ProfileMedium, 4},
		{"large 8-core 16GB", 8, 16384, ProfileLarge, 8},
		{"high core low ram clamped to tiny", 16, 1024, ProfileTiny, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := Classify(tt.cpus, tt.ramMB)
			if b.Profile != tt.wantTier {
				t.Errorf("Classify(%d, %d) tier = %s, want %s", tt.cpus, tt.ramMB, b.Profile, tt.wantTier)
			}
			if b.WorkerConcurrency != tt.wantWorker {
				t.Errorf("Classify(%d, %d) workers = %d, want %d", tt.cpus, tt.ramMB, b.WorkerConcurrency, tt.wantWorker)
			}
		})
	}
}

func TestCurrentDoesNotPanic(t *testing.T) {
	b := Current()
	if b.CPUs < 1 {
		t.Errorf("expected at least 1 CPU, got %d", b.CPUs)
	}
	if b.Profile == "" {
		t.Errorf("expected non-empty profile")
	}
}
