// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// 定义了KnownAddress类型，即地址仓库中每条地址记录的格式

package addrmgr

import (
	"time"

	"github.com/btcsuite/btcd/wire"
)

// KnownAddress tracks information about a known network address that is used
// to determine how viable an address is.
type KnownAddress struct {
	na          *wire.NetAddress //从addr消息获知的节点的IPv4或者IPv6地址，请注意，我们看到KnownAddress序列化后，在peers.json中有“.onion”的地址，它是由特定的支持Tor的IPv6地址转换而来
	srcAddr     *wire.NetAddress //addr消息的源，也是当前节点
	attempts    int              //连接成功之前尝试连接的次数
	lastattempt time.Time        //最近一次尝试连接的时间点
	lastsuccess time.Time        //最近一次尝试连接成功的时间点
	tried       bool             //标识是否已经尝试连接过，已经tried过的地址将被放入TriedBuckets
	refs        int              // reference count of new buckets 该地址所属的NewBucket的个数，默认最大个数是8
}

// NetAddress returns the underlying wire.NetAddress associated with the
// known address.
func (ka *KnownAddress) NetAddress() *wire.NetAddress {
	return ka.na
}

// LastAttempt returns the last time the known address was attempted.
func (ka *KnownAddress) LastAttempt() time.Time {
	return ka.lastattempt
}

// chance returns the selection probability for a known address.  The priority
// depends upon how recently the address has been seen, how recently it was last
// attempted and how often attempts to connect to it have failed.
func (ka *KnownAddress) chance() float64 {
	now := time.Now()
	lastAttempt := now.Sub(ka.lastattempt)

	if lastAttempt < 0 {
		lastAttempt = 0
	}

	c := 1.0

	// Very recent attempts are less likely to be retried.
	if lastAttempt < 10*time.Minute {
		c *= 0.01
	}

	// Failed attempts deprioritise.
	for i := ka.attempts; i > 0; i-- {
		c /= 1.5
	}

	return c
}

// isBad returns true if the address in question has not been tried in the last
// minute and meets one of the following criteria:
// 1) It claims to be from the future
// 2) It hasn't been seen in over a month
// 3) It has failed at least three times and never succeeded
// 4) It has failed ten times in the last week
// All addresses that meet these criteria are assumed to be worthless and not
// worth keeping hold of.
func (ka *KnownAddress) isBad() bool {
	if ka.lastattempt.After(time.Now().Add(-1 * time.Minute)) {
		return false
	}

	// From the future?
	if ka.na.Timestamp.After(time.Now().Add(10 * time.Minute)) {
		return true
	}

	// Over a month old?
	if ka.na.Timestamp.Before(time.Now().Add(-1 * numMissingDays * time.Hour * 24)) {
		return true
	}

	// Never succeeded?
	if ka.lastsuccess.IsZero() && ka.attempts >= numRetries {
		return true
	}

	// Hasn't succeeded in too long?
	if !ka.lastsuccess.After(time.Now().Add(-1*minBadDays*time.Hour*24)) &&
		ka.attempts >= maxFailures {
		return true
	}

	return false
}
