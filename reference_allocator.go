// SPDX-License-Identifier: MIT

package cotp

import (
	"fmt"
	"sync"
)

// referenceAllocator is a process-reusable collision-safe SRC-REF allocator.
// It tracks active references, skips zero, and skips still-active values after wrap.
type referenceAllocator struct {
	mu     sync.Mutex
	next   uint16
	active map[uint16]struct{}
}

func newReferenceAllocator() *referenceAllocator {
	return &referenceAllocator{
		next:   1,
		active: make(map[uint16]struct{}),
	}
}

// Allocate returns a non-zero reference that is not currently active.
func (a *referenceAllocator) Allocate() (uint16, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.active == nil {
		a.active = make(map[uint16]struct{})
	}
	if len(a.active) >= 65535 {
		return 0, fmt.Errorf("reference allocator exhausted: %w", ErrInvalidConfig)
	}
	for tried := 0; tried < 65536; tried++ {
		cand := a.next
		a.next++
		if cand == 0 {
			continue
		}
		if _, used := a.active[cand]; used {
			continue
		}
		a.active[cand] = struct{}{}
		return cand, nil
	}
	return 0, fmt.Errorf("reference allocator exhausted: %w", ErrInvalidConfig)
}

// Release removes a reference from the active set. Idempotent; safe to call once per terminal transition.
func (a *referenceAllocator) Release(ref uint16) {
	if ref == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.active, ref)
}

// Active reports whether ref is currently allocated.
func (a *referenceAllocator) Active(ref uint16) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.active[ref]
	return ok
}

// Len returns the number of active references (test helper).
func (a *referenceAllocator) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.active)
}
