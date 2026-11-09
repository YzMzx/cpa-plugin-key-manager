package handler

import (
	"testing"
	"time"
)

func TestPlainDateUsesSelectedTimezone(t *testing.T) {
	for _, zone := range []string{"Asia/Shanghai", "America/New_York", "UTC"} {
		got, err := parseTimeParamInZone("2026-11-01", zone)
		if err != nil {
			t.Fatal(err)
		}
		loc, _ := time.LoadLocation(zone)
		want := time.Date(2026, 11, 1, 0, 0, 0, 0, loc)
		if !got.Equal(want) {
			t.Fatalf("zone %s got %s want %s", zone, got, want)
		}
	}
}

func TestInvalidDateAndTimezoneAreRejected(t *testing.T) {
	for _, input := range []struct{ value, zone string }{{"2026-99-01", "UTC"}, {"not-a-date", "UTC"}, {"2026-11-01", "invalid/timezone"}} {
		if _, err := parseTimeParamInZone(input.value, input.zone); err == nil {
			t.Fatalf("accepted %+v", input)
		}
	}
}
