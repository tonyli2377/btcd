// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package connmgr

import (
	"fmt"
	mrand "math/rand"
	"net"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

const (
	// These constants are used by the DNS seed code to pick a random last
	// seen time.
	secondsIn3Days int32 = 24 * 60 * 60 * 3
	secondsIn4Days int32 = 24 * 60 * 60 * 4
)

// OnSeed is the signature of the callback function which is invoked when DNS
// seeding is succesfull.
type OnSeed func(addrs []*wire.NetAddress)

// LookupFunc is the signature of the DNS lookup function.
type LookupFunc func(string) ([]net.IP, error)

// SeedFromDNS uses DNS seeding to populate the address manager with peers.
// Btcd节点在chaincfg/params.go中内置了种子节点
// 然而，在ConnMgr连接种子节点之前，必须进行DNS Lookup查询它们对应的IP地址，这是在SeedFromDNS()中完成的
// 它的主要步骤为:
// （1）调用lookupFn()进行DNS resolve，将种子节点的域名解析为IP地址
// （2）将种子节点的IP地址封装为协议地址wire.NetAddress，其中主要是增加了地址的时效性，这里将地址的时效随机地设为3到7天。
func SeedFromDNS(chainParams *chaincfg.Params, reqServices wire.ServiceFlag, lookupFn LookupFunc, seedFn OnSeed) {
	for _, dnsseed := range chainParams.DNSSeeds {
		var host string
		if !dnsseed.HasFiltering || reqServices == wire.SFNodeNetwork {
			host = dnsseed.Host
		} else {
			host = fmt.Sprintf("x%x.%s", uint64(reqServices), dnsseed.Host)
		}

		go func(host string) {
			randSource := mrand.New(mrand.NewSource(time.Now().UnixNano()))
			seedpeers, err := lookupFn(host) // 将种子节点的域名解析为IP地址
			if err != nil {
				log.Infof("DNS discovery failed on seed %s: %v", host, err)
				return
			}
			numPeers := len(seedpeers)

			log.Infof("%d addresses found from DNS seed %s", numPeers, host)

			if numPeers == 0 {
				return
			}
			addresses := make([]*wire.NetAddress, len(seedpeers))
			// if this errors then we have *real* problems
			intPort, _ := strconv.Atoi(chainParams.DefaultPort)
			//将种子节点的IP地址封装为协议地址wire.NetAddress，其中主要是增加了地址的时效性，这里将地址的时效随机地设为3到7天
			for i, peer := range seedpeers {
				addresses[i] = wire.NewNetAddressTimestamp(
					// bitcoind seeds with addresses from
					// a time randomly selected between 3
					// and 7 days ago.
					time.Now().Add(-1*time.Second*time.Duration(secondsIn3Days+randSource.Int31n(secondsIn4Days))),
					0, peer, uint16(intPort))
			}

			seedFn(addresses)
		}(host)
	}
}
