// SPDX-License-Identifier: MIT

package cotp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type deadlineRecorder struct {
	mu   sync.Mutex
	last time.Time
	sets int
}

func (r *deadlineRecorder) set(t time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last = t
	r.sets++
	return nil
}

func (r *deadlineRecorder) get() (time.Time, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last, r.sets
}

func TestDirectionDeadline_AppliesAndRestores(t *testing.T) {
	t.Parallel()
	rec := &deadlineRecorder{}
	d := newDirectionDeadline(rec.set)
	dl := time.Now().Add(time.Hour)
	ctx, cancel := context.WithDeadline(context.Background(), dl)
	defer cancel()
	disarm, err := d.arm(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := rec.get(); !got.Equal(dl) {
		t.Fatalf("armed deadline = %v, want %v", got, dl)
	}
	disarm()
	disarm() // idempotent
	if got, n := rec.get(); !got.IsZero() || n != 2 {
		t.Fatalf("after disarm: %v (%d sets), want zero after 2 sets", got, n)
	}
}

func TestDirectionDeadline_BackgroundSetsNothing(t *testing.T) {
	t.Parallel()
	rec := &deadlineRecorder{}
	disarm, err := newDirectionDeadline(rec.set).arm(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, n := rec.get(); n != 0 {
		t.Fatalf("arm(Background) made %d sets", n)
	}
	disarm()
	if got, _ := rec.get(); !got.IsZero() {
		t.Fatalf("after disarm: %v", got)
	}
}

func TestDirectionDeadline_DoneContext(t *testing.T) {
	t.Parallel()
	rec := &deadlineRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	disarm, err := newDirectionDeadline(rec.set).arm(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	disarm()
	if _, n := rec.get(); n != 0 {
		t.Fatalf("done ctx made %d sets", n)
	}
}

func TestDirectionDeadline_CancelInterrupts(t *testing.T) {
	t.Parallel()
	rec := &deadlineRecorder{}
	ctx, cancel := context.WithCancel(context.Background())
	disarm, err := newDirectionDeadline(rec.set).arm(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got, _ := rec.get(); got.Equal(pastDeadline) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancel did not set a past deadline")
		}
		time.Sleep(time.Millisecond)
	}
	disarm()
	if got, _ := rec.get(); !got.IsZero() {
		t.Fatalf("after disarm: %v", got)
	}
}

// A cancellation racing disarm must never leave a past deadline behind for
// the next operation (the v1.0.4 watcher goroutine could).
func TestDirectionDeadline_CancelRaceNeverPoisons(t *testing.T) {
	t.Parallel()
	rec := &deadlineRecorder{}
	d := newDirectionDeadline(rec.set)
	for i := 0; i < 2000; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		disarm, err := d.arm(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); cancel() }()
		go func() { defer wg.Done(); disarm() }()
		wg.Wait()
		time.Sleep(time.Microsecond)
		if got, _ := rec.get(); !got.IsZero() {
			t.Fatalf("iteration %d: deadline %v left after disarm", i, got)
		}
	}
}

func TestOpLock_HonoursContext(t *testing.T) {
	t.Parallel()
	l := newOpLock()
	if err := l.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := l.lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended lock = %v", err)
	}
	got := make(chan error, 1)
	go func() { got <- l.lock(context.Background()) }()
	time.Sleep(5 * time.Millisecond)
	l.unlock()
	if err := <-got; err != nil {
		t.Fatal(err)
	}
	l.unlock()
}

func TestArmHandshake_NilConn(t *testing.T) {
	t.Parallel()
	if _, err := armHandshake(nil, context.Background()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
}

func TestCtxDoneErr(t *testing.T) {
	t.Parallel()
	if err := ctxDoneErr(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Deadline passed but timer not yet observed is still DeadlineExceeded.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := ctxDoneErr(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
