package nodeagent

import "testing"

func TestParseCPUStat(t *testing.T) {
	content := []byte("cpu  100 20 30 400 50 6 7 8 0 0\ncpu0 50 10 15 200 25 3 3 4 0 0\nintr 123\n")
	s, err := parseCPUStat(content)
	if err != nil {
		t.Fatalf("parseCPUStat: %v", err)
	}
	// total = 100+20+30+400+50+6+7+8 = 621; idle = 400+50 = 450.
	if s.total != 621 || s.idle != 450 {
		t.Errorf("got total=%v idle=%v, want 621/450", s.total, s.idle)
	}
}

func TestParseCPUStatRejectsGarbage(t *testing.T) {
	if _, err := parseCPUStat([]byte("intr 1\nctxt 2\n")); err == nil {
		t.Error("want error when no aggregate cpu line")
	}
	if _, err := parseCPUStat([]byte("cpu  1 2 x\n")); err == nil {
		t.Error("want error on non-numeric jiffie field")
	}
}

func TestCPUPctBetween(t *testing.T) {
	a := cpuSample{total: 1000, idle: 800}
	b := cpuSample{total: 1200, idle: 850}
	// delta total 200, delta idle 50 -> busy 150/200 = 75%.
	if got := cpuPctBetween(a, b); got != 75 {
		t.Errorf("got %v, want 75", got)
	}
	// Zero/negative delta must report 0, never NaN.
	if got := cpuPctBetween(b, b); got != 0 {
		t.Errorf("zero delta: got %v, want 0", got)
	}
}

func TestParseMemInfo(t *testing.T) {
	content := []byte("MemTotal:       1000 kB\nMemFree:         100 kB\nMemAvailable:    400 kB\nBuffers:          50 kB\n")
	got, err := parseMemInfo(content)
	if err != nil {
		t.Fatalf("parseMemInfo: %v", err)
	}
	// used = (1000-400)/1000 = 60%.
	if got != 60 {
		t.Errorf("got %v, want 60", got)
	}
}

func TestParseMemInfoFallsBackToMemFree(t *testing.T) {
	content := []byte("MemTotal:       1000 kB\nMemFree:         250 kB\n")
	got, err := parseMemInfo(content)
	if err != nil {
		t.Fatalf("parseMemInfo: %v", err)
	}
	// No MemAvailable: used = (1000-250)/1000 = 75%.
	if got != 75 {
		t.Errorf("got %v, want 75", got)
	}
}

func TestParseMemInfoRejectsMissingTotal(t *testing.T) {
	if _, err := parseMemInfo([]byte("MemFree: 100 kB\n")); err == nil {
		t.Error("want error when MemTotal absent")
	}
}

func TestParseLoadavg(t *testing.T) {
	got, err := parseLoadavg([]byte("0.52 0.58 0.59 1/234 5678\n"))
	if err != nil {
		t.Fatalf("parseLoadavg: %v", err)
	}
	if got != 0.52 {
		t.Errorf("got %v, want 0.52", got)
	}
	if _, err := parseLoadavg([]byte("")); err == nil {
		t.Error("want error on empty loadavg")
	}
	if _, err := parseLoadavg([]byte("abc 1 2\n")); err == nil {
		t.Error("want error on non-numeric loadavg")
	}
}
