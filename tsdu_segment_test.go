// SPDX-License-Identifier: MIT

package cotp

import (
	"bytes"
	"context"
	"testing"
)

func refMinimalDT(t testing.TB, chunk []byte, eot bool) []byte {
	t.Helper()
	want, err := (&DT{EOT: eot, UserData: chunk}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return want
}

// TestAppendMinimalDTMatchesMarshal: the segment WriteTSDU sends is the DT
// that MarshalBinary encodes, below, at and above the kept buffer size.
func TestAppendMinimalDTMatchesMarshal(t *testing.T) {
	var c Conn
	for _, n := range []int{1, 2, 100, segBufKeepLength - minimalDTOverhead, segBufKeepLength - minimalDTOverhead + 1, maxSegmentPayload(65531)} {
		chunk := bytes.Repeat([]byte{0xC3}, n)
		for _, eot := range []bool{false, true} {
			if got, want := c.appendMinimalDT(chunk, eot), refMinimalDT(t, chunk, eot); !bytes.Equal(got, want) {
				t.Fatalf("chunk %d eot %v: got % x..., want % x...", n, eot, got[:3], want[:3])
			}
		}
	}
}

func FuzzAppendMinimalDT(f *testing.F) {
	f.Add([]byte{1}, true)
	f.Add(bytes.Repeat([]byte{7}, 300), false)
	f.Fuzz(func(t *testing.T, chunk []byte, eot bool) {
		if len(chunk) == 0 || len(chunk) > maxSegmentPayload(65531) {
			t.Skip()
		}
		var c Conn
		if got, want := c.appendMinimalDT(chunk, eot), refMinimalDT(t, chunk, eot); !bytes.Equal(got, want) {
			t.Fatalf("got % x, want % x", got, want)
		}
	})
}

// TestSegmentBufferBounded: a Conn keeps at most segBufKeepLength octets for
// its segments, and a larger segment neither replaces nor aliases them.
func TestSegmentBufferBounded(t *testing.T) {
	var c Conn
	steps := []struct{ chunk, wantCap int }{
		{maxSegmentPayload(65531), 0},
		{100, minimalDTOverhead + 100},
		{segBufKeepLength - minimalDTOverhead, segBufKeepLength},
		{maxSegmentPayload(65531), segBufKeepLength},
		{1, segBufKeepLength},
	}
	for i, s := range steps {
		seg := c.appendMinimalDT(make([]byte, s.chunk), true)
		kept := cap(c.segBuf)
		if kept != s.wantCap {
			t.Fatalf("step %d (chunk %d): kept %d octets, want %d", i, s.chunk, kept, s.wantCap)
		}
		if len(seg) > segBufKeepLength && kept > 0 && &seg[0] == &c.segBuf[:1][0] {
			t.Fatalf("step %d: a large segment uses the kept buffer", i)
		}
	}
}

// TestReadTSDU_OneSegmentResultOwned: a TSDU of one segment is returned
// without a copy; it ends at its length and later reads do not change it.
func TestReadTSDU_OneSegmentResultOwned(t *testing.T) {
	cli, srv := openPipePair(t, 1024, DefaultMaxTSDULength)
	first, second := bytes.Repeat([]byte{0x11}, 300), bytes.Repeat([]byte{0x22}, 300)
	errCh := make(chan error, 1)
	go func() {
		for _, p := range [][]byte{first, second} {
			if err := cli.WriteTSDU(context.Background(), p); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()
	a, err := srv.ReadTSDU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := srv.ReadTSDU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if cap(a) != len(a) || cap(b) != len(b) {
		t.Fatalf("capacity beyond length: %d/%d, %d/%d", cap(a), len(a), cap(b), len(b))
	}
	if !bytes.Equal(a, first) || !bytes.Equal(b, second) {
		t.Fatalf("payloads changed")
	}
	a[0] = 0xFF
	if b[0] != 0x22 {
		t.Fatalf("results share memory")
	}
}

// TestAppendMinimalDTAllocations: after the first segment, building one of at
// most segBufKeepLength octets does not allocate; a larger one allocates once.
func TestAppendMinimalDTAllocations(t *testing.T) {
	for _, n := range []int{1, 1021, segBufKeepLength - minimalDTOverhead, segBufKeepLength - minimalDTOverhead + 1} {
		var c Conn
		chunk := make([]byte, n)
		c.appendMinimalDT(chunk, true)
		allocs := testing.AllocsPerRun(100, func() { c.appendMinimalDT(chunk, true) })
		want := 0.0
		if minimalDTOverhead+n > segBufKeepLength {
			want = 1
		}
		if allocs != want {
			t.Errorf("chunk %d: %v allocations, want %v", n, allocs, want)
		}
	}
}
