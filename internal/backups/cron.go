package backups

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// NextRun returns the next time strictly after from that matches the 5-field
// cron expression. Fields are minute, hour, day-of-month, month, day-of-week.
//
// The supported subset is what a backup schedule needs: "*", "n", "n-m",
// "n,m", and "*/s" (or "n-m/s"). Names ("MON") are not supported. When both
// day-of-month and day-of-week are restricted, a day matches if EITHER matches,
// which is standard cron behavior.
//
// ponytail: no seconds field, no L/W/# modifiers, no timezone handling — the
// caller passes a UTC time and gets a UTC time back. Add those when a plan
// actually needs them; the parser rejects anything outside the subset.
func NextRun(expr string, from time.Time) (time.Time, error) {
	fields, err := parseCron(expr)
	if err != nil {
		return time.Time{}, err
	}
	// Start at the next whole minute. A schedule never fires mid-minute.
	t := from.UTC().Truncate(time.Minute).Add(time.Minute)
	// Two years of minutes is far past any sane schedule; a match that far
	// out means the expression can never fire (e.g. Feb 31).
	limit := t.AddDate(2, 0, 0)
	for !t.After(limit) {
		if fields.match(t) {
			return t, nil
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, fmt.Errorf("backups: cron %q never matches within 2 years of %s", expr, from.Format(time.RFC3339))
}

type cronFields struct {
	minute [60]bool
	hour   [24]bool
	dom    [32]bool // 1-31
	month  [13]bool // 1-12
	dow    [7]bool  // 0-6, Sunday = 0
	anyDOM bool
	anyDOW bool
}

func (f cronFields) match(t time.Time) bool {
	if !f.minute[t.Minute()] || !f.hour[t.Hour()] || !f.month[int(t.Month())] {
		return false
	}
	domOK := f.dom[t.Day()]
	dowOK := f.dow[int(t.Weekday())]
	switch {
	case f.anyDOM && f.anyDOW:
		return true
	case f.anyDOM:
		return dowOK
	case f.anyDOW:
		return domOK
	default:
		return domOK || dowOK
	}
}

func parseCron(expr string) (cronFields, error) {
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return cronFields{}, fmt.Errorf("backups: cron %q must have exactly 5 fields", expr)
	}
	var f cronFields
	var err error
	if err = fill(parts[0], 0, 59, f.minute[:]); err != nil {
		return cronFields{}, fmt.Errorf("backups: cron minute: %w", err)
	}
	if err = fill(parts[1], 0, 23, f.hour[:]); err != nil {
		return cronFields{}, fmt.Errorf("backups: cron hour: %w", err)
	}
	f.anyDOM = parts[2] == "*"
	if err = fill(parts[2], 1, 31, f.dom[1:]); err != nil {
		return cronFields{}, fmt.Errorf("backups: cron day-of-month: %w", err)
	}
	if err = fill(parts[3], 1, 12, f.month[1:]); err != nil {
		return cronFields{}, fmt.Errorf("backups: cron month: %w", err)
	}
	f.anyDOW = parts[4] == "*"
	if err = fill(parts[4], 0, 6, f.dow[:]); err != nil {
		return cronFields{}, fmt.Errorf("backups: cron day-of-week: %w", err)
	}
	return f, nil
}

// fill sets slots[v-lo] for every value the field selects. slots must be
// indexed from 0 covering [lo, hi].
func fill(field string, lo, hi int, slots []bool) error {
	for _, item := range strings.Split(field, ",") {
		start, end, step, err := parseItem(item, lo, hi)
		if err != nil {
			return err
		}
		for v := start; v <= end; v += step {
			slots[v-lo] = true
		}
	}
	return nil
}

func parseItem(item string, lo, hi int) (start, end, step int, err error) {
	step = 1
	if base, s, ok := strings.Cut(item, "/"); ok {
		step, err = strconv.Atoi(s)
		if err != nil || step < 1 {
			return 0, 0, 0, fmt.Errorf("bad step %q", item)
		}
		item = base
	}
	switch {
	case item == "*":
		start, end = lo, hi
	case strings.Contains(item, "-"):
		a, b, _ := strings.Cut(item, "-")
		start, err = strconv.Atoi(a)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("bad range %q", item)
		}
		end, err = strconv.Atoi(b)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("bad range %q", item)
		}
	default:
		start, err = strconv.Atoi(item)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("bad value %q", item)
		}
		end = start
	}
	if start < lo || end > hi || start > end {
		return 0, 0, 0, fmt.Errorf("value %q outside %d-%d", item, lo, hi)
	}
	return start, end, step, nil
}
