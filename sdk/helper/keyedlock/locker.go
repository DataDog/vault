// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

/*
Package keyedlock provides a mechanism for creating finer-grained locking to help
free up more global locks to handle other tasks.

The implementation looks close to a sync.Mutex, however the user must provide a
reference to use to refer to the underlying lock when locking and unlocking,
and unlock may generate an error.

If a lock with a given name does not exist when `Lock` is called, one is
created.
Lock references are automatically cleaned up on `Unlock` if nothing else is
waiting for the lock.
*/
package keyedlock

import (
	"cmp"
	"errors"
	"fmt"
	"iter"
	"slices"
	"sync"
	"sync/atomic"
)

// ErrNoSuchLock is returned when the requested lock does not exist
var ErrNoSuchLock = errors.New("no such lock")

// Locker provides a locking mechanism based on the passed in reference name
type Locker struct {
	mu    sync.Mutex
	locks map[string]*lockCtr

	blockNewLocks     bool
	blockNewLocksCond sync.Cond
}

// lockCtr is used by Locker to represent a lock with a given name.
type lockCtr struct {
	mu sync.Mutex
	// waiters is the number of waiters waiting to acquire the lock
	// this is int32 instead of uint32 so we can add `-1` in `dec()`
	waiters int32
}

// inc increments the number of waiters waiting for the lock
func (l *lockCtr) inc() {
	atomic.AddInt32(&l.waiters, 1)
}

// dec decrements the number of waiters waiting on the lock
func (l *lockCtr) dec() {
	atomic.AddInt32(&l.waiters, -1)
}

// count gets the current number of waiters
func (l *lockCtr) count() int32 {
	return atomic.LoadInt32(&l.waiters)
}

// Lock locks the mutex
func (l *lockCtr) Lock() {
	l.mu.Lock()
}

// Unlock unlocks the mutex
func (l *lockCtr) Unlock() {
	l.mu.Unlock()
}

// New creates a new Locker
func New() *Locker {
	var l Locker
	l.lazyInit()
	return &l
}

func (l *Locker) lazyInit() {
	if l.locks == nil {
		l.locks = make(map[string]*lockCtr)
		l.blockNewLocksCond = sync.Cond{L: &l.mu}
	}
}

// Lock locks a mutex with the given name. If it doesn't exist, one is created
func (l *Locker) Lock(name string) {
	l.mu.Lock()
	l.lazyInit()
	// Wait if we are not allowed to create new locks
	for l.blockNewLocks {
		l.blockNewLocksCond.Wait()
	}

	nameLock, exists := l.locks[name]
	if !exists {
		nameLock = &lockCtr{}
		l.locks[name] = nameLock
	}

	// increment the nameLock waiters while inside the main mutex
	// this makes sure that the lock isn't deleted if `Lock` and `Unlock` are called concurrently
	nameLock.inc()
	l.mu.Unlock()

	// Lock the nameLock outside the main mutex so we don't block other operations
	// once locked then we can decrement the number of waiters for this lock
	nameLock.Lock()
	nameLock.dec()
}

// Unlock unlocks the mutex with the given name
// If the given lock is not being waited on by any other callers, it is deleted
func (l *Locker) Unlock(name string) error {
	l.mu.Lock()
	nameLock, exists := l.locks[name]
	if !exists {
		l.mu.Unlock()
		return ErrNoSuchLock
	}

	if nameLock.count() == 0 {
		delete(l.locks, name)
	}
	l.mu.Unlock()

	nameLock.Unlock()
	return nil
}

// MustUnlock unlocks the mutex and panics if the lock does not exist
func (l *Locker) MustUnlock(name string) {
	if err := l.Unlock(name); err != nil {
		panic(fmt.Errorf("failed to unlock %s: %w", name, err))
	}
}

func (l *Locker) LockMultiple(keys []string) func() {
	if len(keys) == 0 {
		return func() {}
	} else if len(keys) == 1 {
		key := keys[0]
		l.Lock(key)
		return func() { l.MustUnlock(key) }
	}
	return l.LockMultipleSeq(slices.Values(keys))
}

func (l *Locker) LockMultipleSeq(keys iter.Seq[string]) func() {
	// Sort keys so we lock them in consistent order to avoid deadlocks, see [locksutil.CreateLocks]
	sortedKeys := slices.Sorted(keys)
	if len(sortedKeys) == 0 {
		return func() {}
	} else if len(sortedKeys) == 1 {
		key := sortedKeys[0]
		l.Lock(key)
		return func() { l.MustUnlock(key) }
	}

	type lockWithKey struct {
		key  string
		lock *lockCtr
	}
	lockCtrs := make([]lockWithKey, 0, len(sortedKeys))

	l.mu.Lock()
	l.lazyInit()
	// Wait if we are not allowed to create new locks
	for l.blockNewLocks {
		l.blockNewLocksCond.Wait()
	}
	// Create locks and increment waiter count for each key
	var prev string
	for idx, key := range sortedKeys {
		if idx > 0 && key == prev {
			// Skip duplicate key
			continue
		}
		prev = key

		nameLock, exists := l.locks[key]
		if !exists {
			nameLock = &lockCtr{}
			l.locks[key] = nameLock
		}
		lockCtrs = append(lockCtrs, lockWithKey{
			key:  key,
			lock: nameLock,
		})
		nameLock.inc()
	}
	l.mu.Unlock()

	// Lock all the locks
	for _, lock := range lockCtrs {
		lock.lock.Lock()
		lock.lock.dec()
	}

	return func() {
		l.mu.Lock()
		for _, lock := range lockCtrs {
			if lock.lock.count() == 0 {
				delete(l.locks, lock.key)
			}
		}
		l.mu.Unlock()
		for _, lock := range lockCtrs {
			lock.lock.Unlock()
		}
	}
}

func (l *Locker) LockAll() func() {
	l.mu.Lock()
	l.lazyInit()
	// Wait if we are not allowed to create new locks
	for l.blockNewLocks {
		l.blockNewLocksCond.Wait()
	}
	// From now on, prevent new locks from being created
	l.blockNewLocks = true
	// Create list of existing locks and increment waiter count on each of them
	type lockWithKey struct {
		key  string
		lock *lockCtr
	}
	lockCtrs := make([]lockWithKey, 0, len(l.locks))
	for key, lock := range l.locks {
		lockCtrs = append(lockCtrs, lockWithKey{
			key:  key,
			lock: lock,
		})
		lock.inc()
	}
	l.mu.Unlock()

	// Sort existing locks so we lock them in consistent order to avoid deadlocks, see [locksutil.CreateLocks]
	lockCtrs = slices.SortedFunc(slices.Values(lockCtrs), func(a, b lockWithKey) int {
		return cmp.Compare(a.key, b.key)
	})

	// Lock all the locks
	for _, lock := range lockCtrs {
		lock.lock.Lock()
		lock.lock.dec()
	}

	return func() {
		l.mu.Lock()
		for _, lock := range lockCtrs {
			if lock.lock.count() == 0 {
				delete(l.locks, lock.key)
			}
		}
		// Allow new locks to be created again
		l.blockNewLocks = false
		l.mu.Unlock()
		l.blockNewLocksCond.Broadcast()

		for _, lock := range lockCtrs {
			lock.lock.Unlock()
		}
	}
}
