// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
// 用于防止DDoS攻击的动态计分器

package connmgr

import (
	"fmt"
	"math"
	"sync"
	"time"
)

const (
	// Halflife defines the time (in seconds) by which the transient part
	// of the ban score decays to one half of it's original value.
	Halflife = 60

	// lambda is the decaying constant.
	lambda = math.Ln2 / Halflife

	// Lifetime defines the maximum age of the transient part of the ban
	// score to be considered a non-zero score (in seconds).
	Lifetime = 1800

	// precomputedLen defines the amount of decay factors (one per second) that
	// should be precomputed at initialization.
	precomputedLen = 64
)

// precomputedFactor stores precomputed exponential decay factors for the first
// 'precomputedLen' seconds starting from t == 0.
var precomputedFactor [precomputedLen]float64

// init precomputes decay factors.
func init() {
	for i := range precomputedFactor {
		precomputedFactor[i] = math.Exp(-1.0 * float64(i) * lambda)
	}
}

// decayFactor returns the decay factor at t seconds, using precalculated values
// if available, or calculating the factor if needed.
// 衰减系数是按时间间隔呈指数分布
// 这里的时间间隔是指当前取值时刻距上一次主动调节persistent或者transistent值的时间差
func decayFactor(t int64) float64 {
	if t < precomputedLen {
		return precomputedFactor[t]
	}
	return math.Exp(-1.0 * float64(t) * lambda)
}

// DynamicBanScore provides dynamic ban scores consisting of a persistent and a
// decaying component. The persistent score could be utilized to create simple
// additive banning policies similar to those found in other bitcoin node
// implementations.
//
// The decaying score enables the creation of evasive logic which handles
// misbehaving peers (especially application layer DoS attacks) gracefully
// by disconnecting and banning peers attempting various kinds of flooding.
// DynamicBanScore allows these two approaches to be used in tandem.
//
// Zero value: Values of type DynamicBanScore are immediately ready for use upon
// declaration.
// DynamicBanScore提供的分值是由一个不变值和瞬时值构成的
type DynamicBanScore struct {
	lastUnix   int64      //上一次调整分值的Unix时间点
	transient  float64    //分值的浮动衰减部分
	persistent uint32     //分值中不会自动衰减的部分
	mtx        sync.Mutex //保护transient和persistent的互斥锁
}

// String returns the ban score as a human-readable string.
func (s *DynamicBanScore) String() string {
	s.mtx.Lock()
	r := fmt.Sprintf("persistent %v + transient %v at %v = %v as of now",
		s.persistent, s.transient, s.lastUnix, s.Int())
	s.mtx.Unlock()
	return r
}

// Int returns the current ban score, the sum of the persistent and decaying
// scores.
//
// This function is safe for concurrent access.
func (s *DynamicBanScore) Int() uint32 {
	s.mtx.Lock()
	r := s.int(time.Now())
	s.mtx.Unlock()
	return r
}

// Increase increases both the persistent and decaying scores by the values
// passed as parameters. The resulting score is returned.
//
// This function is safe for concurrent access.
func (s *DynamicBanScore) Increase(persistent, transient uint32) uint32 {
	s.mtx.Lock()
	r := s.increase(persistent, transient, time.Now())
	s.mtx.Unlock()
	return r
}

// Reset set both persistent and decaying scores to zero.
//
// This function is safe for concurrent access.
func (s *DynamicBanScore) Reset() {
	s.mtx.Lock()
	s.persistent = 0
	s.transient = 0
	s.lastUnix = 0
	s.mtx.Unlock()
}

// int returns the ban score, the sum of the persistent and decaying scores at a
// given point in time.
//
// This function is not safe for concurrent access. It is intended to be used
// internally and during testing.
// DynamicBanScore最后的分值等于persistent加上transient乘以一个衰减系数后的和。其中衰减系数随时间变化，它由decayFactor()决定
func (s *DynamicBanScore) int(t time.Time) uint32 {
	dt := t.Unix() - s.lastUnix
	if s.transient < 1 || dt < 0 || Lifetime < dt {
		return s.persistent
	}
	return s.persistent + uint32(s.transient*decayFactor(dt))
}

// increase increases the persistent, the decaying or both scores by the values
// passed as parameters. The resulting score is calculated as if the action was
// carried out at the point time represented by the third parameter. The
// resulting score is returned.
//
// This function is not safe for concurrent access.
// 主动调节score值时，先将persistent值直接相加，然后算出传入时刻t的transient值，再与传入的transient值相加后得到新的transient值，
// 新的persistent与新的transient值相加后得到新的score。实际上，就是t时刻的score加上传入的persistent和transient即得到新的score。
// Peer之间交换消息时，每一个Peer连接会有一个动态计分器来监控它们之间收发消息的频率，
// 太频繁地收到某个Peer发过来的消息时，将被怀疑遭到DDoS攻击，从而主动断开与它的连接
func (s *DynamicBanScore) increase(persistent, transient uint32, t time.Time) uint32 {
	s.persistent += persistent
	tu := t.Unix()
	dt := tu - s.lastUnix

	if transient > 0 {
		if Lifetime < dt {
			s.transient = 0
		} else if s.transient > 1 && dt > 0 {
			s.transient *= decayFactor(dt) //算出传入时刻t的transient值
		}
		s.transient += float64(transient) //与传入的transient值相加后得到新的transient值
		s.lastUnix = tu
	}
	return s.persistent + uint32(s.transient) //新的persistent与新的transient值相加后得到新的score
}
