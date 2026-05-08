package scanorch_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"local/elsereno/internal/scanorch"
)

// newSchedReq is a helper for tests. The input parameter is
// retained even though every callsite passes "stdin" — keeps
// the call shape obvious + lets future tests use list:/nmap:
// inputs without rewriting the helper.
//
//nolint:unparam // input documents intent across callsites
func newSchedReq(name, input string, interval int) scanorch.CreateScheduleRequest {
	return scanorch.CreateScheduleRequest{
		Name:            name,
		Template:        scanorch.SubmitRequest{Input: input, Plugins: []string{"banner"}},
		IntervalSeconds: interval,
	}
}

// TestMemoryScheduleStore_Create_Happy: round-trip the
// minimum valid create request.
func TestMemoryScheduleStore_Create_Happy(t *testing.T) {
	s := scanorch.NewMemoryScheduleStore()
	sched, err := s.Create(context.Background(), newSchedReq("daily", "stdin", 86400), "alice")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if sched.Name != "daily" {
		t.Errorf("Name = %q", sched.Name)
	}
	if sched.IntervalSeconds != 86400 {
		t.Errorf("IntervalSeconds = %d", sched.IntervalSeconds)
	}
	if !sched.Enabled {
		t.Errorf("Enabled should default to true")
	}
	if len(sched.ID) != 16 {
		t.Errorf("ID = %q (len %d)", sched.ID, len(sched.ID))
	}
}

// TestMemoryScheduleStore_Create_NameRequired.
func TestMemoryScheduleStore_Create_NameRequired(t *testing.T) {
	s := scanorch.NewMemoryScheduleStore()
	_, err := s.Create(context.Background(), scanorch.CreateScheduleRequest{
		Template:        scanorch.SubmitRequest{Input: "stdin"},
		IntervalSeconds: 60,
	}, "alice")
	if !errors.Is(err, scanorch.ErrScheduleNameRequired) {
		t.Errorf("err = %v, want ErrScheduleNameRequired", err)
	}
}

// TestMemoryScheduleStore_Create_TemplateInputRequired.
func TestMemoryScheduleStore_Create_TemplateInputRequired(t *testing.T) {
	s := scanorch.NewMemoryScheduleStore()
	_, err := s.Create(context.Background(), scanorch.CreateScheduleRequest{
		Name:            "x",
		IntervalSeconds: 60,
	}, "alice")
	if !errors.Is(err, scanorch.ErrScheduleTemplateInputRequired) {
		t.Errorf("err = %v, want ErrScheduleTemplateInputRequired", err)
	}
}

// TestMemoryScheduleStore_Create_IntervalClamping: 1s clamps
// up to 60s, 99 days clamps down to 7 days.
func TestMemoryScheduleStore_Create_IntervalClamping(t *testing.T) {
	s := scanorch.NewMemoryScheduleStore()
	sLow, _ := s.Create(context.Background(), newSchedReq("low", "stdin", 1), "alice")
	if sLow.IntervalSeconds != 60 {
		t.Errorf("low clamp: IntervalSeconds = %d, want 60", sLow.IntervalSeconds)
	}
	sHigh, _ := s.Create(context.Background(), newSchedReq("high", "stdin", 99*86400), "alice")
	if sHigh.IntervalSeconds != 7*86400 {
		t.Errorf("high clamp: IntervalSeconds = %d, want 604800", sHigh.IntervalSeconds)
	}
}

// TestMemoryScheduleStore_GetDeleteList: round-trip CRUD.
func TestMemoryScheduleStore_GetDeleteList(t *testing.T) {
	s := scanorch.NewMemoryScheduleStore()
	sched, _ := s.Create(context.Background(), newSchedReq("zeta", "stdin", 60), "alice")
	_, _ = s.Create(context.Background(), newSchedReq("alpha", "stdin", 60), "alice")

	got, err := s.Get(context.Background(), sched.ID)
	if err != nil {
		t.Fatalf("Get err = %v", err)
	}
	if got.ID != sched.ID {
		t.Errorf("Get ID = %q, want %q", got.ID, sched.ID)
	}

	all, _ := s.List(context.Background())
	if len(all) != 2 {
		t.Errorf("List len = %d, want 2", len(all))
	}
	// Sorted by Name → alpha first, zeta second.
	if all[0].Name != "alpha" || all[1].Name != "zeta" {
		t.Errorf("List order = [%q, %q], want [alpha, zeta]", all[0].Name, all[1].Name)
	}

	if err := s.Delete(context.Background(), sched.ID); err != nil {
		t.Fatalf("Delete err = %v", err)
	}
	if _, err := s.Get(context.Background(), sched.ID); !errors.Is(err, scanorch.ErrScheduleNotFound) {
		t.Errorf("Get after Delete err = %v, want ErrScheduleNotFound", err)
	}
}

// TestMemoryScheduleStore_MarkFired stamps LastFiredAt.
func TestMemoryScheduleStore_MarkFired(t *testing.T) {
	s := scanorch.NewMemoryScheduleStore()
	sched, _ := s.Create(context.Background(), newSchedReq("daily", "stdin", 86400), "alice")
	now := time.Now().UTC()
	if err := s.MarkFired(context.Background(), sched.ID, now); err != nil {
		t.Fatalf("MarkFired err = %v", err)
	}
	got, _ := s.Get(context.Background(), sched.ID)
	if got.LastFiredAt.IsZero() {
		t.Errorf("LastFiredAt should be populated")
	}
}

// TestMemoryScheduleStore_SetEnabled.
func TestMemoryScheduleStore_SetEnabled(t *testing.T) {
	s := scanorch.NewMemoryScheduleStore()
	sched, _ := s.Create(context.Background(), newSchedReq("daily", "stdin", 60), "alice")
	if err := s.SetEnabled(context.Background(), sched.ID, false); err != nil {
		t.Fatalf("SetEnabled err = %v", err)
	}
	got, _ := s.Get(context.Background(), sched.ID)
	if got.Enabled {
		t.Errorf("Enabled should be false after SetEnabled(false)")
	}
}

// TestScanSchedule_IsDue: never-fired schedules are due
// immediately; recent-fired schedules wait for interval.
func TestScanSchedule_IsDue(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name     string
		schedule scanorch.ScanSchedule
		expected bool
	}{
		{"never-fired-enabled",
			scanorch.ScanSchedule{Enabled: true, IntervalSeconds: 60},
			true},
		{"never-fired-disabled",
			scanorch.ScanSchedule{Enabled: false, IntervalSeconds: 60},
			false},
		{"fired-recently-not-due",
			scanorch.ScanSchedule{
				Enabled:         true,
				IntervalSeconds: 3600,
				LastFiredAt:     now.Add(-10 * time.Second),
			},
			false},
		{"fired-long-ago-due",
			scanorch.ScanSchedule{
				Enabled:         true,
				IntervalSeconds: 3600,
				LastFiredAt:     now.Add(-2 * time.Hour),
			},
			true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.schedule.IsDue(now); got != tc.expected {
				t.Errorf("IsDue = %v, want %v", got, tc.expected)
			}
		})
	}
}

// TestScheduler_Tick_FiresDueSchedule: a never-fired
// enabled schedule is fired on the next Tick.
func TestScheduler_Tick_FiresDueSchedule(t *testing.T) {
	scanStore := scanorch.NewMemoryStore()
	schedStore := scanorch.NewMemoryScheduleStore()
	sched, _ := schedStore.Create(context.Background(), newSchedReq("daily", "stdin", 86400), "alice")
	var fired int
	sc := &scanorch.Scheduler{
		ScheduleStore: schedStore,
		ScanStore:     scanStore,
		OnFire: func(string, scanorch.Job) {
			fired++
		},
	}
	sc.Tick(context.Background())
	if fired != 1 {
		t.Errorf("OnFire called %d times, want 1", fired)
	}
	got, _ := schedStore.Get(context.Background(), sched.ID)
	if got.LastFiredAt.IsZero() {
		t.Errorf("LastFiredAt should be stamped after fire")
	}
	jobs, _ := scanStore.List(context.Background(), 10)
	if len(jobs) != 1 {
		t.Errorf("ScanStore has %d jobs, want 1", len(jobs))
	}
}

// TestScheduler_Tick_SkipsDisabled.
func TestScheduler_Tick_SkipsDisabled(t *testing.T) {
	scanStore := scanorch.NewMemoryStore()
	schedStore := scanorch.NewMemoryScheduleStore()
	sched, _ := schedStore.Create(context.Background(), newSchedReq("daily", "stdin", 86400), "alice")
	_ = schedStore.SetEnabled(context.Background(), sched.ID, false)
	sc := &scanorch.Scheduler{ScheduleStore: schedStore, ScanStore: scanStore}
	sc.Tick(context.Background())
	jobs, _ := scanStore.List(context.Background(), 10)
	if len(jobs) != 0 {
		t.Errorf("ScanStore got %d jobs, want 0 (schedule was disabled)", len(jobs))
	}
}

// TestScheduler_Tick_SkipsRecentlyFired: a schedule that
// fired 10s ago with a 1h interval should NOT re-fire on the
// next tick.
func TestScheduler_Tick_SkipsRecentlyFired(t *testing.T) {
	scanStore := scanorch.NewMemoryStore()
	schedStore := scanorch.NewMemoryScheduleStore()
	sched, _ := schedStore.Create(context.Background(), newSchedReq("hourly", "stdin", 3600), "alice")
	_ = schedStore.MarkFired(context.Background(), sched.ID, time.Now().UTC().Add(-10*time.Second))
	sc := &scanorch.Scheduler{ScheduleStore: schedStore, ScanStore: scanStore}
	sc.Tick(context.Background())
	jobs, _ := scanStore.List(context.Background(), 10)
	if len(jobs) != 0 {
		t.Errorf("ScanStore got %d jobs, want 0 (within interval)", len(jobs))
	}
}

// TestScheduler_Run_RespectsCancel: Run returns ctx.Err()
// after cancellation.
func TestScheduler_Run_RespectsCancel(t *testing.T) {
	scanStore := scanorch.NewMemoryStore()
	schedStore := scanorch.NewMemoryScheduleStore()
	sc := &scanorch.Scheduler{
		ScheduleStore: schedStore,
		ScanStore:     scanStore,
		TickInterval:  20 * time.Second, // out of range → defaults to 30s; we don't wait
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sc.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// TestScheduler_Run_NoScheduleStore returns the sentinel.
func TestScheduler_Run_NoScheduleStore(t *testing.T) {
	sc := &scanorch.Scheduler{ScanStore: scanorch.NewMemoryStore()}
	if err := sc.Run(context.Background()); !errors.Is(err, scanorch.ErrSchedulerNoScheduleStore) {
		t.Errorf("err = %v, want ErrSchedulerNoScheduleStore", err)
	}
}

// TestScheduler_Run_NoScanStore returns the sentinel.
func TestScheduler_Run_NoScanStore(t *testing.T) {
	sc := &scanorch.Scheduler{ScheduleStore: scanorch.NewMemoryScheduleStore()}
	if err := sc.Run(context.Background()); !errors.Is(err, scanorch.ErrSchedulerNoScanStore) {
		t.Errorf("err = %v, want ErrSchedulerNoScanStore", err)
	}
}
