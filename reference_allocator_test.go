// SPDX-License-Identifier: MIT

package cotp

import (
	"sync"
	"testing"
)

func TestReferenceAllocator(t *testing.T) {
	t.Run("case_58_wrap_skips_active", func(t *testing.T) {
		a := newReferenceAllocator()
		a.next = 0xFFFE
		r1, err := a.Allocate()
		if err != nil || r1 != 0xFFFE {
			t.Fatalf("r1=%d err=%v", r1, err)
		}
		r2, err := a.Allocate()
		if err != nil || r2 != 0xFFFF {
			t.Fatalf("r2=%d err=%v", r2, err)
		}
		r3, err := a.Allocate()
		if err != nil || r3 != 1 {
			t.Fatalf("r3=%d err=%v", r3, err)
		}
		a.next = 0xFFFE
		r4, err := a.Allocate()
		if err != nil {
			t.Fatal(err)
		}
		if r4 == 0 || r4 == 0xFFFE || r4 == 0xFFFF || r4 == 1 {
			t.Fatalf("should skip active refs, got %d", r4)
		}
		if !a.Active(r4) {
			t.Fatalf("r4=%d should be active", r4)
		}
	})
	t.Run("case_59_release_exactly_once", func(t *testing.T) {
		a := newReferenceAllocator()
		r, err := a.Allocate()
		if err != nil {
			t.Fatal(err)
		}
		if a.Len() != 1 {
			t.Fatalf("len=%d", a.Len())
		}
		a.Release(r)
		a.Release(r) // idempotent
		if a.Len() != 0 || a.Active(r) {
			t.Fatalf("len=%d active=%v", a.Len(), a.Active(r))
		}
	})
	t.Run("case_60_concurrent_no_duplicates", func(t *testing.T) {
		a := newReferenceAllocator()
		const n = 1000
		refs := make([]uint16, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			i := i
			go func() {
				defer wg.Done()
				refs[i], errs[i] = a.Allocate()
			}()
		}
		wg.Wait()
		seen := make(map[uint16]struct{}, n)
		for i := 0; i < n; i++ {
			if errs[i] != nil {
				t.Fatalf("alloc %d: %v", i, errs[i])
			}
			if refs[i] == 0 {
				t.Fatal("zero ref")
			}
			if _, ok := seen[refs[i]]; ok {
				t.Fatalf("duplicate %d", refs[i])
			}
			seen[refs[i]] = struct{}{}
		}
		if len(seen) != n {
			t.Fatalf("got %d want %d", len(seen), n)
		}
	})
	t.Run("never_returns_zero", func(t *testing.T) {
		a := newReferenceAllocator()
		a.next = 0
		ref, err := a.Allocate()
		if err != nil || ref == 0 {
			t.Fatalf("ref=%d err=%v", ref, err)
		}
	})
}
