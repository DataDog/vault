// Copyright IBM Corp. 2016, 2025
// SPDX-License-Identifier: MPL-2.0

package cacheutil

import lru "github.com/hashicorp/golang-lru/v2"

var _ TwoQueueCacheInterface[complex64, complex128] = &lru.TwoQueueCache[complex64, complex128]{}

// TwoQueueCacheInterface is satisfied by lru.TwoQueueCache. Depending on the
// interface rather than the concrete type lets tests wrap the cache to
// observe concurrent access.
type TwoQueueCacheInterface[K comparable, V any] interface {
	Get(key K) (value V, ok bool)
	Add(key K, value V)
	Len() int
	Resize(size int) (evicted int)
	Keys() []K
	Values() []V
	Remove(key K)
	Purge()
	Contains(key K) bool
	Peek(key K) (value V, ok bool)
}
