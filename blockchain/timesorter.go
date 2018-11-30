// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
// 实现了支持升序排序的时间戳集合类型timeSorter，timeSorter实际上是[]int64类型，这是Go语言特性的一个体现，
// 即通过类型定义可以扩展任意类型，包括基础类型的方法集

package blockchain

// timeSorter implements sort.Interface to allow a slice of timestamps to
// be sorted.
type timeSorter []int64

// Len returns the number of timestamps in the slice.  It is part of the
// sort.Interface implementation.
func (s timeSorter) Len() int {
	return len(s)
}

// Swap swaps the timestamps at the passed indices.  It is part of the
// sort.Interface implementation.
func (s timeSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less returns whether the timstamp with index i should sort before the
// timestamp with index j.  It is part of the sort.Interface implementation.
func (s timeSorter) Less(i, j int) bool {
	return s[i] < s[j]
}
