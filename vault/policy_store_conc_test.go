// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"container/list"
	"context"
	"maps"
	"math/rand"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/vault/internalshared/namespace"
	"github.com/hashicorp/vault/sdk/helper/cacheutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/petermattis/goid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ lockerInterface = &lockOwnerTracker{}

// lockOwnerTracker wraps a keyed lock that satisfies lockerInterface.
// It tracks which keys are locked and by which goroutine.
type lockOwnerTracker struct {
	ownerGoidByKey sync.Map
	underlying     lockerInterface

	// Might as well report some stats while we're at it
	waiterCnt  atomic.Int32
	lockedCnt  atomic.Int32
	maxWaiters atomic.Int32
	maxLocked  atomic.Int32
}

func (l *lockOwnerTracker) Lock(name string) {
	myGoid := goid.Get()

	waiterCnt := l.waiterCnt.Add(1)
	storeIfMax(&l.maxWaiters, waiterCnt)

	l.underlying.Lock(name)

	l.waiterCnt.Add(-1)
	lockedCnt := l.lockedCnt.Add(1)
	storeIfMax(&l.maxLocked, lockedCnt)

	l.ownerGoidByKey.Store(name, myGoid)
}

func (l *lockOwnerTracker) MustUnlock(name string) {
	l.lockedCnt.Add(-1)

	l.ownerGoidByKey.Delete(name)
	l.underlying.MustUnlock(name)
}

func storeIfMax(dest *atomic.Int32, value int32) {
	for {
		cur := dest.Load()
		if cur > value {
			break
		}
		if dest.CompareAndSwap(cur, value) {
			break
		}
	}
}

var _ syncMapInterface = &syncMapWriteListener{}

// syncMapWriteListener wraps a sync.Map and calls a callback before each write/delete operation.
type syncMapWriteListener struct {
	syncMapInterface
	beforeWrite func(key any)
}

func (s *syncMapWriteListener) Store(key, value interface{}) {
	s.beforeWrite(key)
	s.syncMapInterface.Store(key, value)
}

func (s *syncMapWriteListener) Delete(i interface{}) {
	s.beforeWrite(i)
	s.syncMapInterface.Delete(i)
}

var _ logical.Storage = &storageOperationListener{}

// storageOperationListener wraps a logical.Storage and calls a callback before each operation.
type storageOperationListener struct {
	underlying   logical.Storage
	beforeList   func(prefix string)
	beforeGet    func(key string)
	beforePut    func(key string)
	beforeDelete func(key string)
}

func (s *storageOperationListener) List(ctx context.Context, s2 string) ([]string, error) {
	s.beforeList(s2)
	return s.underlying.List(ctx, s2)
}

func (s *storageOperationListener) Get(ctx context.Context, s2 string) (*logical.StorageEntry, error) {
	s.beforeGet(s2)
	return s.underlying.Get(ctx, s2)
}

func (s *storageOperationListener) Put(ctx context.Context, entry *logical.StorageEntry) error {
	s.beforePut(entry.Key)
	return s.underlying.Put(ctx, entry)
}

func (s *storageOperationListener) Delete(ctx context.Context, s2 string) error {
	s.beforeDelete(s2)
	return s.underlying.Delete(ctx, s2)
}

var _ cacheutil.TwoQueueCacheInterface[string, *Policy] = &twoQueueCacheWriteListener{}

// twoQueueCacheListener wraps a lrumetrics.TwoQueueCacheInterface and calls a callback before each write operation.
type twoQueueCacheWriteListener struct {
	cacheutil.TwoQueueCacheInterface[string, *Policy]
	beforeWrite func(key any)
}

func (t *twoQueueCacheWriteListener) Add(key string, value *Policy) {
	t.beforeWrite(key)
	t.TwoQueueCacheInterface.Add(key, value)
}

func (t *twoQueueCacheWriteListener) Remove(key string) {
	t.beforeWrite(key)
	t.TwoQueueCacheInterface.Remove(key)
}

// mockConcurrencyCheckedCore creates a test Vault cluster and augments the policy store on the core with concurrency checks.
func mockConcurrencyCheckedCore(t testing.TB, disableCache bool) (*Core, *PolicyStore) {
	core, ps := mockPolicyWithCore(t, disableCache)

	// Track the owner of each lock in the keyed lock
	ownerTracker := &lockOwnerTracker{
		underlying: ps.keyedModifyLock,
	}
	t.Cleanup(func() {
		t.Logf("max waiters: %d, max in lock: %d", ownerTracker.maxWaiters.Load(), ownerTracker.maxLocked.Load())
	})
	// Assert that the current goroutine has locked the supplied key
	assertKeyLockedByMe := func(cacheKey string) {
		ownerGoid, ok := ownerTracker.ownerGoidByKey.Load(cacheKey)
		require.True(t, ok)
		myGoid := goid.Get()
		assert.Equal(t, ownerGoid, myGoid)
	}
	// Only the owner of the lock is allowed to write to the policyTypeMap
	beforePolicyTypeMapWrite := func(key any) {
		keyStr, ok := key.(string)
		require.True(t, ok)
		assertKeyLockedByMe(keyStr)
	}
	// Only the owner of the lock is allowed to issue requests to the storage backend
	beforeStorageOp := func(key string) {
		assertKeyLockedByMe(ps.cacheKey(namespace.RootNamespace, key))
	}
	// Only the owner of the lock is allowed to write to the caches
	beforeCacheWrite := func(key any) {
		keyStr, ok := key.(string)
		require.True(t, ok)
		assertKeyLockedByMe(keyStr)
	}

	ps.keyedModifyLock = ownerTracker
	ps.policyTypeMap = &syncMapWriteListener{
		syncMapInterface: ps.policyTypeMap,
		beforeWrite:      beforePolicyTypeMapWrite,
	}
	for _, bv := range []*BarrierView{ps.aclView, ps.rgpView, ps.egpView} {
		bv.storage = logical.NewStorageView(&storageOperationListener{
			underlying:   bv.storage,
			beforeList:   func(prefix string) {}, // List ops never need to lock
			beforeGet:    beforeStorageOp,
			beforePut:    beforeStorageOp,
			beforeDelete: beforeStorageOp,
		}, "")
	}
	for _, cache := range []*cacheutil.TwoQueueCacheInterface[string, *Policy]{&ps.tokenPoliciesLRU, &ps.egpLRU} {
		if *cache != nil {
			*cache = &twoQueueCacheWriteListener{
				TwoQueueCacheInterface: *cache,
				beforeWrite:            beforeCacheWrite,
			}
		}
	}
	return core, ps
}

// policyState represents the state of a policy in the policy store. Possible values:
// - if the policy does not exist: { exists: false, rawContents: "" }
// - if the policy exists:         { exists: true,  rawContents: "<contents of the policy>" }
type policyState struct {
	exists      bool
	rawContents string
}

// policyStateSet represents the set of possible states of a policy in the policy store.
type policyStateSet struct {
	sync.Mutex
	// ordered list of [*policyState]s writes that have finished
	// states that are known to be invalid are pruned
	commited list.List
	// set of [*policyState]s that are currently being written
	ongoingWrites map[*policyState]struct{}
	// set of read operations on this policy
	ongoingReads map[*readHandle]struct{}

	// stats
	maxUncertainty              int // max simultaneous possible states that we have seen for this policy
	maxUncertaintySeenByReaders int // max possible states that we have seen for this policy while a read was in progress
}

func newPolicyStateSet() *policyStateSet {
	set := &policyStateSet{
		ongoingWrites: map[*policyState]struct{}{},
		ongoingReads:  map[*readHandle]struct{}{},
	}
	// Add initial empty policy state
	set.commited.PushFront(&policyState{})
	return set
}

// policyStateEstimator tracks the possible states of policies in the policy store, using the following rules:
//   - Before initiating a write, the new policy state is added to the "ongoing" set.
//   - After the write has completed, the new state is moved from the "ongoing" set to the "commited" list.
//     Also, any states that were in the "commited" list before the write was initiated can be considered overwritten
//     so we discard them.
//   - At any point, the possible states of a policy are the union of the "ongoing" set and the "commited" list.
//   - Reads on the policy store can take some time to complete, so they also need to subscribe to any new writes that
//     happen during the read.
type policyStateEstimator struct {
	statesByKey map[string]*policyStateSet
}

// beginWrite should be called before starting a write operation.
func (p *policyStateEstimator) beginWrite(key string, newState policyState) *writeHandle {
	ss := p.statesByKey[key]
	ss.Lock()
	defer ss.Unlock()

	// Add new state to the ongoing set
	ss.ongoingWrites[&newState] = struct{}{}

	// Add new state to any ongoing read operations
	for rh := range ss.ongoingReads {
		rh.possibleStates = append(rh.possibleStates, &newState)
	}

	// update stats
	ss.maxUncertainty = max(ss.maxUncertainty, ss.commited.Len()+len(ss.ongoingWrites))

	return &writeHandle{
		stateSet: ss,
		newState: &newState,
		// Save the list of commited states before the write was initiated
		commitedBefore: ss.commited.Back(),
	}
}

// writeHandle is a handle to a write operation that is in progress.
type writeHandle struct {
	stateSet       *policyStateSet
	newState       *policyState
	commitedBefore *list.Element
}

// commit should be called after the write operation has completed.
func (h *writeHandle) commit() {
	h.stateSet.Lock()
	defer h.stateSet.Unlock()

	// Remove all states that were commited before the write was initiated
	for cur := h.commitedBefore; cur != nil; {
		prev := cur.Prev()
		h.stateSet.commited.Remove(cur)
		cur = prev
	}

	// Delete the new state from the ongoing set
	delete(h.stateSet.ongoingWrites, h.newState)

	// Add the new state to the commited list
	h.stateSet.commited.PushBack(h.newState)
}

func (p *policyStateEstimator) beginRead(key string) *readHandle {
	ss := p.statesByKey[key]
	ss.Lock()
	defer ss.Unlock()

	// Collect the current possible states of the policy into a read handle
	rh := &readHandle{
		key:            key,
		ss:             ss,
		possibleStates: make([]*policyState, 0, ss.commited.Len()+len(ss.ongoingWrites)),
	}
	for e := ss.commited.Front(); e != nil; e = e.Next() {
		rh.possibleStates = append(rh.possibleStates, e.Value.(*policyState))
	}
	rh.possibleStates = slices.AppendSeq(rh.possibleStates, maps.Keys(ss.ongoingWrites))

	// Add the read operation to the ongoing set to subscribe to any new writes
	ss.ongoingReads[rh] = struct{}{}

	return rh
}

type readHandle struct {
	key            string
	ss             *policyStateSet
	possibleStates []*policyState
}

func (rh *readHandle) finishAndAssert(t testing.TB, state policyState) {
	rh.ss.Lock()
	// Remove the read operation from the ongoing set
	delete(rh.ss.ongoingReads, rh)
	// update stats
	rh.ss.maxUncertaintySeenByReaders = max(rh.ss.maxUncertaintySeenByReaders, len(rh.possibleStates))
	rh.ss.Unlock()

	// Assert that the state is possible
	for _, s := range rh.possibleStates {
		if *s == state {
			return
		}
	}
	t.Errorf("state %v is not possible for key %s, possible states are: %v", state, rh.key, rh.possibleStates)
}

func Benchmark_TestPolicyStoreConcurrency(b *testing.B) {
	const keyCount = 100

	newRand := func() *rand.Rand {
		return rand.New(rand.NewSource(rand.Int63()))
	}
	localRand := newRand()

	testKeys := []string{
		"keya",
		"KeyA",
		"keyb",
		"keyc",
	}
	for len(testKeys) < keyCount {
		k, err := base62.RandomWithReader(5, localRand)
		require.NoError(b, err)
		testKeys = append(testKeys, k)
	}

	type psOp int
	const (
		psOpSet psOp = iota
		psOpGet
		psOpDelete
	)
	allPsOps := []psOp{psOpSet, psOpGet, psOpDelete}

	policyTypes := []PolicyType{PolicyTypeACL}
	samplePolicyText := `
path "secret/sample" {
	capabilities = ["read", "delete"]
}
`
	samplePolicy, err := ParseACLPolicy(namespace.RootNamespace, samplePolicyText)
	require.NoError(b, err)

	ctx := namespace.RootContext(nil)

	_, ps := mockConcurrencyCheckedCore(b, false)

	stateEstimator := &policyStateEstimator{
		statesByKey: make(map[string]*policyStateSet, len(testKeys)),
	}
	for _, key := range testKeys {
		stateEstimator.statesByKey[ps.sanitizeName(key)] = newPolicyStateSet()
	}

	doRandomOp := func(localRand *rand.Rand) {
		key := pickRandom(localRand, testKeys)
		op := pickRandom(localRand, allPsOps)
		policyType := pickRandom(localRand, policyTypes)
		sanitizedKey := ps.sanitizeName(key)

		switch op {
		case psOpSet:
			clonedPolicy := samplePolicy.ShallowClone()
			clonedPolicy.Name = key
			wh := stateEstimator.beginWrite(sanitizedKey, policyState{exists: true, rawContents: clonedPolicy.Raw})
			err := ps.SetPolicy(ctx, clonedPolicy)
			wh.commit()
			assert.NoError(b, err)
		case psOpGet:
			rh := stateEstimator.beginRead(sanitizedKey)
			policy, err := ps.GetPolicy(ctx, key, policyType)
			assert.NoError(b, err)
			var eps policyState
			if policy != nil {
				eps = policyState{exists: true, rawContents: policy.Raw}
			}
			rh.finishAndAssert(b, eps)
		case psOpDelete:
			wh := stateEstimator.beginWrite(sanitizedKey, policyState{exists: false})
			err := ps.DeletePolicy(ctx, key, policyType)
			wh.commit()
			assert.NoError(b, err)
		}
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		localRand := newRand()
		for pb.Next() {
			doRandomOp(localRand)
		}
	})

	b.StopTimer()

	maxUncertainty := 0
	maxUncertaintySeenByReaders := 0
	for _, ss := range stateEstimator.statesByKey {
		maxUncertainty = max(maxUncertainty, ss.maxUncertainty)
		maxUncertaintySeenByReaders = max(maxUncertaintySeenByReaders, ss.maxUncertaintySeenByReaders)
		assert.Empty(b, ss.ongoingReads)
		assert.Empty(b, ss.ongoingWrites)
	}
	b.Logf("max state uncertainty: %d, max visible uncertainty: %d", maxUncertainty, maxUncertaintySeenByReaders)
}

func pickRandom[S ~[]E, E any](src *rand.Rand, s S) E {
	return s[src.Intn(len(s))]
}
