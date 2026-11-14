// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
)

// heapNow returns the memory statistics after a completed collection, so
// HeapAlloc counts live objects only.
func heapNow() runtime.MemStats {
	var m runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&m)
	return m
}

// TestReadTSDU_PendingReassemblyBudget is the allocation budget of the
// MaxTSDULength limit (SECURITY.md "Resource limits"; the bound is stated on ReadTSDU).
//
// The peer delivers non-final DT segments of one octet of user data, the
// smallest the service accepts, up to one octet below the limit, and then
// nothing. Once the reader has consumed them all and waits for the next
// segment, the test asserts
//
//   - the memory the call holds: at most twice the limit, the documented
//     bound, whatever the number of segments;
//   - the memory the call allocated in total: at most a constant number of
//     octets for each octet received from the stream, so the bookkeeping does
//     not grow faster than the input.
//
// It runs for a small limit and for the default one (the latter without the
// race detector only, see below). It is not parallel: it reads process-wide
// memory statistics.
func TestReadTSDU_PendingReassemblyBudget(t *testing.T) {
	// One TPKT packet carrying a DT with EOT=0 and one octet of user data.
	segment := mustEncodeTPKT(t, mustMarshal(t, &DT{EOT: false, UserData: []byte{0x5A}}))

	const (
		// slack absorbs what the runtime and the test itself allocate
		// (goroutine stacks are not heap, but the scheduler, the channel
		// and the statistics are).
		slack = 256 << 10
		// perOctet is the budget of total allocation per octet received.
		// For each packet the reader allocates the header, the payload and
		// the decoded DT, and the reassembly buffer as it doubles: about 12
		// octets per octet received with segments of one octet (16 under
		// the race detector, which does not pack small objects).
		perOctet = 20
	)

	type budgetCase struct {
		name    string
		maxTSDU int // as configured; 0 selects the default
		limit   int
	}
	cases := []budgetCase{{"64 KiB", 64 << 10, 64 << 10}}
	if raceEnabled {
		// Four million packets take most of a minute under the race
		// detector. The plain run and the 32-bit run have the default limit;
		// the small limit covers the same path here.
		t.Log("built with -race: the default-limit case is left to the run without the race detector")
	} else {
		cases = append(cases, budgetCase{"default limit", 0, DefaultMaxTSDULength})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			segments := tc.limit - 1
			received := int64(segments) * int64(len(segment))
			sc := newScriptConn(&repeatReader{unit: segment, n: segments})
			conn, _ := openScriptConn(t, sc, 1024, tc.maxTSDU)

			before := heapNow()
			errCh := make(chan error, 1)
			go func() {
				_, err := conn.ReadTSDU(context.Background())
				errCh <- err
			}()
			sc.awaitIdle(t) // every segment consumed; ReadTSDU waits for the next one
			held := heapNow()

			live := int64(held.HeapAlloc) - int64(before.HeapAlloc)
			total := int64(held.TotalAlloc - before.TotalAlloc)
			t.Logf("limit %d: %d segments, %d octets received; held %d octets (%.2f x limit), allocated %d octets (%.1f per octet received)",
				tc.limit, segments, received, live, float64(live)/float64(tc.limit), total, float64(total)/float64(received))

			if budget := 2*int64(tc.limit) + slack; live > budget {
				t.Errorf("pending reassembly holds %d octets, budget %d (2 x MaxTSDULength %d + %d)", live, budget, tc.limit, slack)
			}
			if budget := perOctet*received + slack; total > budget {
				t.Errorf("pending reassembly allocated %d octets for %d received, budget %d (%d per octet + %d)", total, received, budget, perOctet, slack)
			}

			// The segments are still pending: the call returns when the
			// connection is closed, and reports the local close.
			if err := conn.Close(); !errors.Is(err, ErrClosed) {
				t.Fatalf("Close = %v, want ErrClosed", err)
			}
			select {
			case err := <-errCh:
				if !errors.Is(err, ErrClosed) {
					t.Fatalf("ReadTSDU = %v, want ErrClosed", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("ReadTSDU did not return after Close")
			}
		})
	}
}

// One octet more than the limit, delivered in the smallest segments, ends
// the connection with ErrTSDUTooLarge at the first octet over the limit; one
// TSDU of exactly the limit is returned whole.
func TestReadTSDU_SmallestSegmentsAtTheLimit(t *testing.T) {
	const limit = 4096
	open := mustEncodeTPKT(t, mustMarshal(t, &DT{EOT: false, UserData: []byte{0x5A}}))
	last := mustEncodeTPKT(t, mustMarshal(t, &DT{EOT: true, UserData: []byte{0x5A}}))

	stream := func(nonFinal int) *bytes.Reader {
		b := bytes.Repeat(open, nonFinal)
		return bytes.NewReader(append(b, last...))
	}

	t.Run("limit", func(t *testing.T) {
		conn, _ := openScriptConn(t, newScriptConn(stream(limit-1)), 1024, limit)
		got, err := conn.ReadTSDU(context.Background())
		if err != nil {
			t.Fatalf("ReadTSDU: %v", err)
		}
		if !bytes.Equal(got, bytes.Repeat([]byte{0x5A}, limit)) {
			t.Fatalf("TSDU of %d octets, want %d octets of 0x5A", len(got), limit)
		}
		if cap(got) != len(got) {
			t.Fatalf("returned TSDU has capacity %d beyond its length %d", cap(got), len(got))
		}
		_ = conn.Close()
	})
	t.Run("limit plus one", func(t *testing.T) {
		conn, _ := openScriptConn(t, newScriptConn(stream(limit)), 1024, limit)
		_, err := conn.ReadTSDU(context.Background())
		if !errors.Is(err, ErrTSDUTooLarge) || !errors.Is(err, ErrIncompleteTSDU) {
			t.Fatalf("ReadTSDU = %v, want ErrTSDUTooLarge joined with ErrIncompleteTSDU", err)
		}
		if conn.terminalKind() != terminalAborted {
			t.Fatal("the connection must be aborted")
		}
	})
}
