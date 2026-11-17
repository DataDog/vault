// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package keyedlock

import (
	"fmt"
	"math/rand"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestLockCounter(t *testing.T) {
	l := &lockCtr{}
	l.inc()

	if l.waiters != 1 {
		t.Fatal("counter inc failed")
	}

	l.dec()
	if l.waiters != 0 {
		t.Fatal("counter dec failed")
	}
}

func TestLockerLock(t *testing.T) {
	l := New()
	l.Lock("test")
	ctr := l.locks["test"]

	if ctr.count() != 0 {
		t.Fatalf("expected waiters to be 0, got :%d", ctr.waiters)
	}

	chDone := make(chan struct{})
	go func() {
		l.Lock("test")
		close(chDone)
	}()

	chWaiting := make(chan struct{})
	go func() {
		for range time.Tick(1 * time.Millisecond) {
			if ctr.count() == 1 {
				close(chWaiting)
				break
			}
		}
	}()

	select {
	case <-chWaiting:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for lock waiters to be incremented")
	}

	select {
	case <-chDone:
		t.Fatal("lock should not have returned while it was still held")
	default:
	}

	if err := l.Unlock("test"); err != nil {
		t.Fatal(err)
	}

	select {
	case <-chDone:
	case <-time.After(3 * time.Second):
		t.Fatalf("lock should have completed")
	}

	if ctr.count() != 0 {
		t.Fatalf("expected waiters to be 0, got: %d", ctr.count())
	}
}

func TestLockerUnlock(t *testing.T) {
	l := New()

	l.Lock("test")
	l.Unlock("test")

	chDone := make(chan struct{})
	go func() {
		l.Lock("test")
		close(chDone)
	}()

	select {
	case <-chDone:
	case <-time.After(3 * time.Second):
		t.Fatalf("lock should not be blocked")
	}
}

func TestLockerConcurrency(t *testing.T) {
	l := New()

	var wg sync.WaitGroup
	for i := 0; i <= 10000; i++ {
		wg.Add(1)
		go func() {
			l.Lock("test")
			// if there is a concurrency issue, will very likely panic here
			l.Unlock("test")
			wg.Done()
		}()
	}

	chDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(chDone)
	}()

	select {
	case <-chDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for locks to complete")
	}

	// Since everything has unlocked this should not exist anymore
	if ctr, exists := l.locks["test"]; exists {
		t.Fatalf("lock should not exist: %v", ctr)
	}
}

func BenchmarkLocker(b *testing.B) {
	l := New()
	for i := 0; i < b.N; i++ {
		l.Lock("test")
		l.Unlock("test")
	}
}

func BenchmarkLockerParallel(b *testing.B) {
	l := New()
	b.SetParallelism(128)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.Lock("test")
			l.Unlock("test")
		}
	})
}

func BenchmarkLockerMoreKeys(b *testing.B) {
	l := New()
	var keys []string
	for i := 0; i < 64; i++ {
		keys = append(keys, strconv.Itoa(i))
	}
	b.SetParallelism(128)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			k := keys[rand.Intn(len(keys))]
			l.Lock(k)
			l.Unlock(k)
		}
	})
}

func BenchmarkLockerCombinations(b *testing.B) {
	l := New()
	var keys []string
	for i := 0; i < 64; i++ {
		keys = append(keys, strconv.Itoa(i))
	}
	guarded := make(map[string]*sync.Mutex, len(keys))
	for _, k := range keys {
		guarded[k] = &sync.Mutex{}
	}
	ensureGuarded := func(k string) {
		m := guarded[k]
		if !m.TryLock() {
			panic("expected lock to be available")
		}
		m.Unlock()
	}

	// Generate list of possible combinations of locking operations
	type opType int
	const (
		lockSingle opType = iota
		lockMultiple
		lockAll
	)
	var opCombos [][]opType
	for _, op := range []opType{lockSingle, lockMultiple, lockAll} {
		ops := []opType{op}
		for _, combo := range opCombos {
			opCombos = append(opCombos, slices.Concat(combo, ops))
		}
		opCombos = append(opCombos, ops)
	}

	// Benchmark each combination
	b.SetParallelism(128)
	for _, opCombo := range opCombos {
		b.Run(fmt.Sprintf("%v", opCombo), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					op := opCombo[rand.Intn(len(opCombo))]
					if op == lockSingle {
						// Lock single key
						k := keys[rand.Intn(len(keys))]
						l.Lock(k)
						ensureGuarded(k)
						l.MustUnlock(k)
					} else if op == lockMultiple {
						// Pick random keys, allowing duplicates
						randKeys := make([]string, 0, 32)
						for i := 0; i < 32; i++ {
							randKeys = append(randKeys, keys[rand.Intn(len(keys))])
						}
						unlock := l.LockMultiple(randKeys)
						for _, k := range randKeys {
							ensureGuarded(k)
						}
						unlock()
					} else if op == lockAll {
						// Lock all
						unlock := l.LockAll()
						for _, k := range keys {
							ensureGuarded(k)
						}
						unlock()
					} else {
						panic("unknown op")
					}
				}
			})
		})
	}
}
