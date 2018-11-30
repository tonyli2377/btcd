// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// 实现Peer地址的存取以及随机选择策略，是AddrManager的主要模块，它将地址集合以特定的形式存于peers.json文件中

package addrmgr

import (
	"container/list"
	crand "crypto/rand" // for seeding
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// AddrManager provides a concurrency safe address manager for caching potential
// peers on the bitcoin network.
type AddrManager struct {
	mtx            sync.Mutex                               //AddrManager的对象锁，保证addrManager是并发安全的
	peersFile      string                                   //存储地址仓库的文件名，默认为“peers.json”。请注意，Bitcoind中的文件名为“peers.data”;
	lookupFunc     func(string) ([]net.IP, error)           //进行DNS Lookup的函数值
	rand           *rand.Rand                               //随机数生成器
	key            [32]byte                                 //32字节的随机数数序列，用于计算NewBucket和TriedBucket的索引
	addrIndex      map[string]*KnownAddress                 // address key to ka for all addrs. 缓存所有KnownAddress的map
	addrNew        [newBucketCount]map[string]*KnownAddress //缓存所有新地址的map slice
	addrTried      [triedBucketCount]*list.List             //缓存所有已经Tried的地址的list slice
	started        int32                                    //用于标识addrmanager已经启动
	shutdown       int32                                    //用于标识addrmanager已经停止
	wg             sync.WaitGroup                           //用于同步退出，addrmanager停止时等待工作协程退出
	quit           chan struct{}                            //用于通知工作协程退出
	nTried         int                                      //记录Tried地址个数
	nNew           int                                      //记录New地址个数
	lamtx          sync.Mutex                               //保护localAddresses的互斥锁
	localAddresses map[string]*localAddress                 //保存已知的本地地址
}

type serializedKnownAddress struct {
	Addr        string
	Src         string
	Attempts    int
	TimeStamp   int64
	LastAttempt int64
	LastSuccess int64
	// no refcount or tried, that is available from context.
}

type serializedAddrManager struct {
	Version      int
	Key          [32]byte
	Addresses    []*serializedKnownAddress
	NewBuckets   [newBucketCount][]string // string is NetAddressKey
	TriedBuckets [triedBucketCount][]string
}

type localAddress struct {
	na    *wire.NetAddress
	score AddressPriority
}

// AddressPriority type is used to describe the hierarchy of local address
// discovery methods.
type AddressPriority int

const (
	// InterfacePrio signifies the address is on a local interface
	InterfacePrio AddressPriority = iota

	// BoundPrio signifies the address has been explicitly bounded to.
	BoundPrio

	// UpnpPrio signifies the address was obtained from UPnP.
	UpnpPrio

	// HTTPPrio signifies the address was obtained from an external HTTP service.
	HTTPPrio

	// ManualPrio signifies the address was provided by --externalip.
	ManualPrio
)

const (
	// needAddressThreshold is the number of addresses under which the
	// address manager will claim to need more addresses.
	needAddressThreshold = 1000

	// dumpAddressInterval is the interval used to dump the address
	// cache to disk for future use.
	dumpAddressInterval = time.Minute * 10

	// triedBucketSize is the maximum number of addresses in each
	// tried address bucket.
	triedBucketSize = 256

	// triedBucketCount is the number of buckets we split tried
	// addresses over.
	triedBucketCount = 64

	// newBucketSize is the maximum number of addresses in each new address
	// bucket.
	newBucketSize = 64

	// newBucketCount is the number of buckets that we spread new addresses
	// over.
	newBucketCount = 1024

	// triedBucketsPerGroup is the number of tried buckets over which an
	// address group will be spread.
	triedBucketsPerGroup = 8

	// newBucketsPerGroup is the number of new buckets over which an
	// source address group will be spread.
	newBucketsPerGroup = 64

	// newBucketsPerAddress is the number of buckets a frequently seen new
	// address may end up in.
	newBucketsPerAddress = 8

	// numMissingDays is the number of days before which we assume an
	// address has vanished if we have not seen it announced  in that long.
	numMissingDays = 30

	// numRetries is the number of tried without a single success before
	// we assume an address is bad.
	numRetries = 3

	// maxFailures is the maximum number of failures we will accept without
	// a success before considering an address bad.
	maxFailures = 10

	// minBadDays is the number of days since the last success before we
	// will consider evicting an address.
	minBadDays = 7

	// getAddrMax is the most addresses that we will send in response
	// to a getAddr (in practise the most addresses we will return from a
	// call to AddressCache()).
	getAddrMax = 2500

	// getAddrPercent is the percentage of total addresses known that we
	// will share with a call to AddressCache.
	getAddrPercent = 23

	// serialisationVersion is the current version of the on-disk format.
	serialisationVersion = 1
)

// updateAddress is a helper function to either update an address already known
// to the address manager, or to add the address if not already known.
// 其主要步骤为:
// （1）判断欲添加的地址netAddr是否是可路由的地址，即除了保留地址以外的地址，如果是不可以路由的地址，则不加入地址仓库
// （2）查询欲添加的地址是否已经在地址集中，如果已经在，且它的时间戳更新或者有支持新的服务，则更新地址集中KnownAddress
// （3）检查如果地址已经在TriedBucket中，则不更新地址仓库；检查如果地址已经位于8个不同的NewBucket中，也不更新仓库；
//      根据地址已经被NewBucket引用的个数，来随机决定是否继续添加到NewBucket中;
// （4）如果欲添加的地址不在现有的地址集中，则需要将其添加到NewBucket中;
// （5）经过上述检查后，如果确定需要添加地址，则调用getNewBucket()找到NewBucket的索引;
// （6）确定了NewBucket的索引后，进一步检查欲添加的地址是否已经在对应的NewBucket时，如果是，则不再加入;
// （7）如果欲放置新地址的NewBucket的Size已经超过newBucketSize(默认值为64)，则调用expireNew()来释放该Bucket里的一些记录。
//      expireNew()的主要思想是将Bucket中时间戳最早的地址或者时间戳是未来时间点、或时间戳是一个月以前、
//      或者尝试连接失败超过3次且没有成功过的地址、或最近一周连接失败超过10次的地址移除。
// （8）最后，将新地址添加到NewBucket里。
func (a *AddrManager) updateAddress(netAddr, srcAddr *wire.NetAddress) {
	// Filter out non-routable addresses. Note that non-routable
	// also includes invalid and local addresses.
	// 判断欲添加的地址netAddr是否是可路由的地址，即除了保留地址以外的地址，如果是不可以路由的地址，则不加入地址仓库
	if !IsRoutable(netAddr) {
		return
	}

	addr := NetAddressKey(netAddr)
	ka := a.find(netAddr)
	if ka != nil {
		// TODO: only update addresses periodically.
		// Update the last seen time and services.
		// note that to prevent causing excess garbage on getaddr
		// messages the netaddresses in addrmaanger are *immutable*,
		// if we need to change them then we replace the pointer with a
		// new copy so that we don't have to copy every na for getaddr.
		// 查询欲添加的地址是否已经在地址集中，如果已经在，且它的时间戳更新或者有支持新的服务，则更新地址集中KnownAddress，
		// 请注意，这里的时间戳是指节点最近获知该地址的时间点
		if netAddr.Timestamp.After(ka.na.Timestamp) ||
			(ka.na.Services&netAddr.Services) !=
				netAddr.Services {
			naCopy := *ka.na
			naCopy.Timestamp = netAddr.Timestamp
			naCopy.AddService(netAddr.Services)
			ka.na = &naCopy
		}

		// If already in tried, we have nothing to do here.
		// 检查如果地址已经在TriedBucket中，则不更新地址仓库；
		if ka.tried {
			return
		}

		// Already at our max?
		// 检查如果地址已经位于8个不同的NewBucket中，也不更新仓库；
		if ka.refs == newBucketsPerAddress {
			return
		}

		// The more entries we have, the less likely we are to add more.
		// likelihood is 2N.
		factor := int32(2 * ka.refs)
		// 根据地址已经被NewBucket引用的个数，来随机决定是否继续添加到NewBucket中
		if a.rand.Int31n(factor) != 0 {
			return
		}
	} else {
		// Make a copy of the net address to avoid races since it is
		// updated elsewhere in the addrmanager code and would otherwise
		// change the actual netaddress on the peer.
		netAddrCopy := *netAddr //如果欲添加的地址不在现有的地址集中，则需要将其添加到NewBucket中
		ka = &KnownAddress{na: &netAddrCopy, srcAddr: srcAddr}
		a.addrIndex[addr] = ka
		a.nNew++
		// XXX time penalty?
	}

	bucket := a.getNewBucket(netAddr, srcAddr) //经过上述检查后，如果确定需要添加地址，则调用getNewBucket()找到NewBucket的索引

	// Already exists?
	// 确定了NewBucket的索引后，进一步检查欲添加的地址是否已经在对应的NewBucket时，如果是，则不再加入
	if _, ok := a.addrNew[bucket][addr]; ok {
		return
	}

	// Enforce max addresses.
	// 如果欲放置新地址的NewBucket的Size已经超过newBucketSize(默认值为64)，则调用expireNew()来释放该Bucket里的一些记录
	// expireNew()的主要思想是将Bucket中时间戳最早的地址或者时间戳是未来时间点、或时间戳是一个月以前、
	// 或者尝试连接失败超过3次且没有成功过的地址、或最近一周连接失败超过10次的地址移除。
	if len(a.addrNew[bucket]) > newBucketSize {
		log.Tracef("new bucket is full, expiring old")
		a.expireNew(bucket)
	}

	// Add to new bucket.
	ka.refs++
	a.addrNew[bucket][addr] = ka //最后，将新地址添加到NewBucket里

	log.Tracef("Added new address %s for a total of %d addresses", addr,
		a.nTried+a.nNew)
}

// expireNew makes space in the new buckets by expiring the really bad entries.
// If no bad entries are available we look at a few and remove the oldest.
func (a *AddrManager) expireNew(bucket int) {
	// First see if there are any entries that are so bad we can just throw
	// them away. otherwise we throw away the oldest entry in the cache.
	// Bitcoind here chooses four random and just throws the oldest of
	// those away, but we keep track of oldest in the initial traversal and
	// use that information instead.
	var oldest *KnownAddress
	for k, v := range a.addrNew[bucket] {
		if v.isBad() {
			log.Tracef("expiring bad address %v", k)
			delete(a.addrNew[bucket], k)
			v.refs--
			if v.refs == 0 {
				a.nNew--
				delete(a.addrIndex, k)
			}
			continue
		}
		if oldest == nil {
			oldest = v
		} else if !v.na.Timestamp.After(oldest.na.Timestamp) {
			oldest = v
		}
	}

	if oldest != nil {
		key := NetAddressKey(oldest.na)
		log.Tracef("expiring oldest address %v", key)

		delete(a.addrNew[bucket], key)
		oldest.refs--
		if oldest.refs == 0 {
			a.nNew--
			delete(a.addrIndex, key)
		}
	}
}

// pickTried selects an address from the tried bucket to be evicted.
// We just choose the eldest. Bitcoind selects 4 random entries and throws away
// the older of them.
func (a *AddrManager) pickTried(bucket int) *list.Element {
	var oldest *KnownAddress
	var oldestElem *list.Element
	for e := a.addrTried[bucket].Front(); e != nil; e = e.Next() {
		ka := e.Value.(*KnownAddress)
		if oldest == nil || oldest.na.Timestamp.After(ka.na.Timestamp) {
			oldestElem = e
			oldest = ka
		}

	}
	return oldestElem
}

func (a *AddrManager) getNewBucket(netAddr, srcAddr *wire.NetAddress) int {
	// bitcoind:
	// doublesha256(key + sourcegroup + int64(doublesha256(key + group + sourcegroup))%bucket_per_source_group) % num_new_buckets
	// NewBucket的索引由AddrManager的随机序列key、地址newAddr及通告该地址的Peer的地址srcAddr共同决定

	data1 := []byte{}
	data1 = append(data1, a.key[:]...)
	data1 = append(data1, []byte(GroupKey(netAddr))...)
	data1 = append(data1, []byte(GroupKey(srcAddr))...)
	hash1 := chainhash.DoubleHashB(data1)
	hash64 := binary.LittleEndian.Uint64(hash1)
	hash64 %= newBucketsPerGroup
	var hashbuf [8]byte
	binary.LittleEndian.PutUint64(hashbuf[:], hash64)
	data2 := []byte{}
	data2 = append(data2, a.key[:]...)
	data2 = append(data2, GroupKey(srcAddr)...)
	data2 = append(data2, hashbuf[:]...)

	hash2 := chainhash.DoubleHashB(data2)
	return int(binary.LittleEndian.Uint64(hash2) % newBucketCount)
}

func (a *AddrManager) getTriedBucket(netAddr *wire.NetAddress) int {
	// bitcoind hashes this as:
	// doublesha256(key + group + truncate_to_64bits(doublesha256(key)) % buckets_per_group) % num_buckets
	data1 := []byte{}
	data1 = append(data1, a.key[:]...)
	data1 = append(data1, []byte(NetAddressKey(netAddr))...)
	hash1 := chainhash.DoubleHashB(data1)
	hash64 := binary.LittleEndian.Uint64(hash1)
	hash64 %= triedBucketsPerGroup
	var hashbuf [8]byte
	binary.LittleEndian.PutUint64(hashbuf[:], hash64)
	data2 := []byte{}
	data2 = append(data2, a.key[:]...)
	data2 = append(data2, GroupKey(netAddr)...)
	data2 = append(data2, hashbuf[:]...)

	hash2 := chainhash.DoubleHashB(data2)
	return int(binary.LittleEndian.Uint64(hash2) % triedBucketCount)
}

// addressHandler is the main handler for the address manager.  It must be run
// as a goroutine.
// 每隔dumpAddressInterval(值为10分钟)调用savePeers()将addrMananager中的地址集写入文件，savePeers()是与deserializePeers()对应的实例化方法
func (a *AddrManager) addressHandler() {
	dumpAddressTicker := time.NewTicker(dumpAddressInterval)
	defer dumpAddressTicker.Stop()
out:
	for {
		select {
		case <-dumpAddressTicker.C:
			a.savePeers()

		case <-a.quit:
			break out
		}
	}
	a.savePeers()
	a.wg.Done()
	log.Trace("Address handler done")
}

// savePeers saves all the known addresses to a file so they can be read back
// in at next run.
func (a *AddrManager) savePeers() {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	// First we make a serialisable datastructure so we can encode it to
	// json.
	sam := new(serializedAddrManager)
	sam.Version = serialisationVersion
	copy(sam.Key[:], a.key[:])

	sam.Addresses = make([]*serializedKnownAddress, len(a.addrIndex))
	i := 0
	for k, v := range a.addrIndex {
		ska := new(serializedKnownAddress)
		ska.Addr = k
		ska.TimeStamp = v.na.Timestamp.Unix()
		ska.Src = NetAddressKey(v.srcAddr)
		ska.Attempts = v.attempts
		ska.LastAttempt = v.lastattempt.Unix()
		ska.LastSuccess = v.lastsuccess.Unix()
		// Tried and refs are implicit in the rest of the structure
		// and will be worked out from context on unserialisation.
		sam.Addresses[i] = ska
		i++
	}
	for i := range a.addrNew {
		sam.NewBuckets[i] = make([]string, len(a.addrNew[i]))
		j := 0
		for k := range a.addrNew[i] {
			sam.NewBuckets[i][j] = k
			j++
		}
	}
	for i := range a.addrTried {
		sam.TriedBuckets[i] = make([]string, a.addrTried[i].Len())
		j := 0
		for e := a.addrTried[i].Front(); e != nil; e = e.Next() {
			ka := e.Value.(*KnownAddress)
			sam.TriedBuckets[i][j] = NetAddressKey(ka.na)
			j++
		}
	}

	w, err := os.Create(a.peersFile)
	if err != nil {
		log.Errorf("Error opening file %s: %v", a.peersFile, err)
		return
	}
	enc := json.NewEncoder(w)
	defer w.Close()
	if err := enc.Encode(&sam); err != nil {
		log.Errorf("Failed to encode file %s: %v", a.peersFile, err)
		return
	}
}

// loadPeers loads the known address from the saved file.  If empty, missing, or
// malformed file, just don't load anything and start fresh
func (a *AddrManager) loadPeers() {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	err := a.deserializePeers(a.peersFile)
	if err != nil {
		log.Errorf("Failed to parse file %s: %v", a.peersFile, err)
		// if it is invalid we nuke the old one unconditionally.
		err = os.Remove(a.peersFile)
		if err != nil {
			log.Warnf("Failed to remove corrupt peers file %s: %v",
				a.peersFile, err)
		}
		a.reset()
		return
	}
	log.Infof("Loaded %d addresses from file '%s'", a.numAddresses(), a.peersFile)
}

//其主要过程为:
//（1）读取文件，并通过json解析器将json文件实例化为serializedAddrManager对象;
//（2）校验版本号，并读取随机数序列Key;
//（3）将serializedKnownAddress解析为KnownAddress，并存入a.addrIndex中。
//     需要注意的是，serializedKnownAddress中的地址均是string，而KnownAddress对应的地址是wire.NetAddress类型，
//     在转换过程中，如果serializedKnownAddress为“.onion”的洋葱地址，则将“.onion”前的字符串转换成大写后进行base32解码，
//     并添加“fd87:d87e:eb43”前缀转换成IPv6地址；如果是hostname，则调用lookupFunc将解析为IP地址；
//     同时，addrIndex的key是地址的string形式，如果是IP:Port的形式，则直接将IP和Port转换为对应的数字字符，
//     如果是以“fd87:d87e:eb43”开头的IPv6地址，则将该地址的后10位进行base32编码并转成小写后的字符串，加上“.onion”后缀转换为洋葱地址形式。
//     具体转换过程在ipString()和HostToNetAddress()中实现;
//（4）以serializedAddrManager的NewBuckets和TriedBuckets中的地址为Key，查找addrIndex中对应的KnownAddress后，填充addrNew和addrTried;
//（5）最后对实例化的结果作Sanity检查，保证一个地址要么在NewBuckets中，要么在TridBuckets中;
func (a *AddrManager) deserializePeers(filePath string) error {
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return nil
	}
	r, err := os.Open(filePath) //读取peers.json文件
	if err != nil {
		return fmt.Errorf("%s error opening file: %v", filePath, err)
	}
	defer r.Close()

	var sam serializedAddrManager
	// 通过json解析器将json文件实例化为serializedAddrManager对象
	dec := json.NewDecoder(r)
	err = dec.Decode(&sam)
	if err != nil {
		return fmt.Errorf("error reading %s: %v", filePath, err)
	}

	//校验版本号
	if sam.Version != serialisationVersion {
		return fmt.Errorf("unknown version %v in serialized "+
			"addrmanager", sam.Version)
	}
	copy(a.key[:], sam.Key[:])

	//读取随机数序列Key
	for _, v := range sam.Addresses {
		ka := new(KnownAddress)
		ka.na, err = a.DeserializeNetAddress(v.Addr)
		if err != nil {
			return fmt.Errorf("failed to deserialize netaddress "+
				"%s: %v", v.Addr, err)
		}
		ka.srcAddr, err = a.DeserializeNetAddress(v.Src)
		if err != nil {
			return fmt.Errorf("failed to deserialize netaddress "+
				"%s: %v", v.Src, err)
		}
		ka.attempts = v.Attempts
		ka.lastattempt = time.Unix(v.LastAttempt, 0)
		ka.lastsuccess = time.Unix(v.LastSuccess, 0)
		a.addrIndex[NetAddressKey(ka.na)] = ka //将serializedKnownAddress解析为KnownAddress，并存入a.addrIndex中
	}

	for i := range sam.NewBuckets {
		for _, val := range sam.NewBuckets[i] {
			ka, ok := a.addrIndex[val]
			if !ok {
				return fmt.Errorf("newbucket contains %s but "+
					"none in address list", val)
			}

			if ka.refs == 0 {
				a.nNew++
			}
			ka.refs++
			a.addrNew[i][val] = ka
		}
	}
	for i := range sam.TriedBuckets {
		for _, val := range sam.TriedBuckets[i] {
			ka, ok := a.addrIndex[val]
			if !ok {
				return fmt.Errorf("Newbucket contains %s but "+
					"none in address list", val)
			}

			ka.tried = true
			a.nTried++
			a.addrTried[i].PushBack(ka)
		}
	}

	// Sanity checking.
	for k, v := range a.addrIndex {
		if v.refs == 0 && !v.tried {
			return fmt.Errorf("address %s after serialisation "+
				"with no references", k)
		}

		if v.refs > 0 && v.tried {
			return fmt.Errorf("address %s after serialisation "+
				"which is both new and tried!", k)
		}
	}

	return nil
}

// DeserializeNetAddress converts a given address string to a *wire.NetAddress
func (a *AddrManager) DeserializeNetAddress(addr string) (*wire.NetAddress, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}

	return a.HostToNetAddress(host, uint16(port), wire.SFNodeNetwork)
}

// Start begins the core address handler which manages a pool of known
// addresses, timeouts, and interval based writes.
// 调用loadPeers()来将peers.json文件中的地址集实例化，然后启动工作协程addressHandler来周期性性向文件保存新的地址。
// loadPeers()主要是调用deserializePeers()将文件反序列化
func (a *AddrManager) Start() {
	// Already started?
	if atomic.AddInt32(&a.started, 1) != 1 {
		return
	}

	log.Trace("Starting address manager")

	// Load peers we already know about from file.
	a.loadPeers()

	// Start the address ticker to save addresses periodically.
	a.wg.Add(1)
	go a.addressHandler()
}

// Stop gracefully shuts down the address manager by stopping the main handler.
func (a *AddrManager) Stop() error {
	if atomic.AddInt32(&a.shutdown, 1) != 1 {
		log.Warnf("Address manager is already in the process of " +
			"shutting down")
		return nil
	}

	log.Infof("Address manager shutting down")
	close(a.quit)
	a.wg.Wait()
	return nil
}

// AddAddresses adds new addresses to the address manager.  It enforces a max
// number of addresses and silently ignores duplicate addresses.  It is
// safe for concurrent access.
func (a *AddrManager) AddAddresses(addrs []*wire.NetAddress, srcAddr *wire.NetAddress) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	for _, na := range addrs {
		a.updateAddress(na, srcAddr)
	}
}

// AddAddress adds a new address to the address manager.  It enforces a max
// number of addresses and silently ignores duplicate addresses.  It is
// safe for concurrent access.
func (a *AddrManager) AddAddress(addr, srcAddr *wire.NetAddress) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	a.updateAddress(addr, srcAddr)
}

// AddAddressByIP adds an address where we are given an ip:port and not a
// wire.NetAddress.
func (a *AddrManager) AddAddressByIP(addrIP string) error {
	// Split IP and port
	addr, portStr, err := net.SplitHostPort(addrIP)
	if err != nil {
		return err
	}
	// Put it in wire.Netaddress
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("invalid ip address %s", addr)
	}
	port, err := strconv.ParseUint(portStr, 10, 0)
	if err != nil {
		return fmt.Errorf("invalid port %s: %v", portStr, err)
	}
	na := wire.NewNetAddressIPPort(ip, uint16(port), 0)
	a.AddAddress(na, na) // XXX use correct src address
	return nil
}

// NumAddresses returns the number of addresses known to the address manager.
func (a *AddrManager) numAddresses() int {
	return a.nTried + a.nNew
}

// NumAddresses returns the number of addresses known to the address manager.
func (a *AddrManager) NumAddresses() int {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	return a.numAddresses()
}

// NeedMoreAddresses returns whether or not the address manager needs more
// addresses.
func (a *AddrManager) NeedMoreAddresses() bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	return a.numAddresses() < needAddressThreshold
}

// AddressCache returns the current address cache.  It must be treated as
// read-only (but since it is a copy now, this is not as dangerous).
func (a *AddrManager) AddressCache() []*wire.NetAddress {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	addrIndexLen := len(a.addrIndex)
	if addrIndexLen == 0 {
		return nil
	}

	allAddr := make([]*wire.NetAddress, 0, addrIndexLen)
	// Iteration order is undefined here, but we randomise it anyway.
	for _, v := range a.addrIndex {
		allAddr = append(allAddr, v.na)
	}

	numAddresses := addrIndexLen * getAddrPercent / 100
	if numAddresses > getAddrMax {
		numAddresses = getAddrMax
	}

	// Fisher-Yates shuffle the array. We only need to do the first
	// `numAddresses' since we are throwing the rest.
	for i := 0; i < numAddresses; i++ {
		// pick a number between current index and the end
		j := rand.Intn(addrIndexLen-i) + i
		allAddr[i], allAddr[j] = allAddr[j], allAddr[i]
	}

	// slice off the limit we are willing to share.
	return allAddr[0:numAddresses]
}

// reset resets the address manager by reinitialising the random source
// and allocating fresh empty bucket storage.
func (a *AddrManager) reset() {

	a.addrIndex = make(map[string]*KnownAddress)

	// fill key with bytes from a good random source.
	io.ReadFull(crand.Reader, a.key[:])
	for i := range a.addrNew {
		a.addrNew[i] = make(map[string]*KnownAddress)
	}
	for i := range a.addrTried {
		a.addrTried[i] = list.New()
	}
}

// HostToNetAddress returns a netaddress given a host address.  If the address
// is a Tor .onion address this will be taken care of.  Else if the host is
// not an IP address it will be resolved (via Tor if required).
func (a *AddrManager) HostToNetAddress(host string, port uint16, services wire.ServiceFlag) (*wire.NetAddress, error) {
	// Tor address is 16 char base32 + ".onion"
	var ip net.IP
	if len(host) == 22 && host[16:] == ".onion" {
		// go base32 encoding uses capitals (as does the rfc
		// but Tor and bitcoind tend to user lowercase, so we switch
		// case here.
		data, err := base32.StdEncoding.DecodeString(
			strings.ToUpper(host[:16]))
		if err != nil {
			return nil, err
		}
		prefix := []byte{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43}
		ip = net.IP(append(prefix, data...))
	} else if ip = net.ParseIP(host); ip == nil {
		ips, err := a.lookupFunc(host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses found for %s", host)
		}
		ip = ips[0]
	}

	return wire.NewNetAddressIPPort(ip, port, services), nil
}

// ipString returns a string for the ip from the provided NetAddress. If the
// ip is in the range used for Tor addresses then it will be transformed into
// the relevant .onion address.
func ipString(na *wire.NetAddress) string {
	if IsOnionCatTor(na) {
		// We know now that na.IP is long enough.
		base32 := base32.StdEncoding.EncodeToString(na.IP[6:])
		return strings.ToLower(base32) + ".onion"
	}

	return na.IP.String()
}

// NetAddressKey returns a string key in the form of ip:port for IPv4 addresses
// or [ip]:port for IPv6 addresses.
func NetAddressKey(na *wire.NetAddress) string {
	port := strconv.FormatUint(uint64(na.Port), 10)

	return net.JoinHostPort(ipString(na), port)
}

// GetAddress returns a single address that should be routable.  It picks a
// random one from the possible addresses with preference given to ones that
// have not been used recently and should not pick 'close' addresses
// consecutively.
// GetAddress()实现了“AddrManage是如何选择一个地址，以供节点建立Peer连接的”
// 其主要步骤为:
// （1）如地址集中NewBucket和TriedBucket，即既有已经尝试连接过的“老”地址，也有未连接过的“新”地址，则按50%的概率随机地从NewBucket或TriedBucket中选择;
// （2）如果决定从TriedBucket中选择，则随机选择一个TriedBucket;
// （3）从随机选择的TriedBucket中，再随机地选择一个地址;
// （4）再判断选择的地址是否满足一个随机条件，如果满足则返回该地址；如果不满足，则增加factor因子以增加满足随机条件的概率，并重复2-4步骤。
//      这个随机条件是: 从0 ~ 102410241024 范围内随机选择一个数，这个随机数是否小于它乘以factor和ka.chance()的结果。
//      可以看到，factor或者ka.chance越大，该条件成立的概率越大;
// （5）如果决定从NewBucket中选择，则采取与TriedBucket相似的步骤随机选择地址;
func (a *AddrManager) GetAddress() *KnownAddress {
	// Protect concurrent access.
	a.mtx.Lock()
	defer a.mtx.Unlock()

	if a.numAddresses() == 0 {
		return nil
	}

	// Use a 50% chance for choosing between tried and new table entries.
	if a.nTried > 0 && (a.nNew == 0 || a.rand.Intn(2) == 0) {
		// Tried entry.
		large := 1 << 30
		factor := 1.0
		for {
			// pick a random bucket.
			bucket := a.rand.Intn(len(a.addrTried))
			if a.addrTried[bucket].Len() == 0 {
				continue
			}

			// Pick a random entry in the list
			e := a.addrTried[bucket].Front()
			for i :=
				a.rand.Int63n(int64(a.addrTried[bucket].Len())); i > 0; i-- {
				e = e.Next()
			}
			ka := e.Value.(*KnownAddress)
			randval := a.rand.Intn(large)
			if float64(randval) < (factor * ka.chance() * float64(large)) {
				log.Tracef("Selected %v from tried bucket",
					NetAddressKey(ka.na))
				return ka
			}
			factor *= 1.2
		}
	} else {
		// new node.
		// XXX use a closure/function to avoid repeating this.
		large := 1 << 30
		factor := 1.0
		for {
			// Pick a random bucket.
			bucket := a.rand.Intn(len(a.addrNew))
			if len(a.addrNew[bucket]) == 0 {
				continue
			}
			// Then, a random entry in it.
			var ka *KnownAddress
			nth := a.rand.Intn(len(a.addrNew[bucket]))
			for _, value := range a.addrNew[bucket] {
				if nth == 0 {
					ka = value
				}
				nth--
			}
			randval := a.rand.Intn(large)
			if float64(randval) < (factor * ka.chance() * float64(large)) {
				log.Tracef("Selected %v from new bucket",
					NetAddressKey(ka.na))
				return ka
			}
			factor *= 1.2
		}
	}
}

func (a *AddrManager) find(addr *wire.NetAddress) *KnownAddress {
	return a.addrIndex[NetAddressKey(addr)]
}

// Attempt increases the given address' attempt counter and updates
// the last attempt time.
func (a *AddrManager) Attempt(addr *wire.NetAddress) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	// find address.
	// Surely address will be in tried by now?
	ka := a.find(addr)
	if ka == nil {
		return
	}
	// set last tried time to now
	ka.attempts++
	ka.lastattempt = time.Now()
}

// Connected Marks the given address as currently connected and working at the
// current time.  The address must already be known to AddrManager else it will
// be ignored.
func (a *AddrManager) Connected(addr *wire.NetAddress) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	ka := a.find(addr)
	if ka == nil {
		return
	}

	// Update the time as long as it has been 20 minutes since last we did
	// so.
	now := time.Now()
	if now.After(ka.na.Timestamp.Add(time.Minute * 20)) {
		// ka.na is immutable, so replace it.
		naCopy := *ka.na
		naCopy.Timestamp = time.Now()
		ka.na = &naCopy
	}
}

// Good marks the given address as good.  To be called after a successful
// connection and version exchange.  If the address is unknown to the address
// manager it will be ignored.
// 调用Good()来将地址从NewBucket移入TriedBucket
// 其主要过程如下:
// （1）查询连成功的地址是否在地址集中，如果不在，则不作处理;
// （2）如果地址在地址集中，则更新该地址的lastsuccess和lastattempt为当前时间点，且将试图重试次数attempts重置;
// （3）如果地址已经在TrieBucket中，则只更新lastsuccess、lastattempt和attempts即可，我们将在GetAddress()中看到，
//      AddrManager选择地址建Peer时，会随机地从NewBucket和TriedBucket中选择;
// （4）如果地址在NewBucket中，则将其从对应的Bucket中移除；请注意，这里记录下了地址所处的NewBucket的索引号oldBucket，它将在后面用到;
// （5）选择一个TriedBucket的索引号，用于将地址添加进对应的Bucket;
// （6）如果选择的TriedBucket未填满(容量为256)，则将地址添加到Bucket;
// （7）如果选择的TriedBucket已经填满，则调用pickTried()从其中选择一个地址，准备将其移动到NewBucket中以腾出空间;
// （8）如果欲移入的NewBucket已经满，则将选择的地址从TriedBucket中移入索引号为oldBucket的NewBucket中，即移入刚刚移除了addr的NewBucket中;
// （9）将连接成功的地址添加到选择的TriedBucket中，通过将listElement的Value直接更新为对应的ka来实现;
// （10）将从TriedBucket中移出的地址移入选择的NewBucket中;
func (a *AddrManager) Good(addr *wire.NetAddress) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	ka := a.find(addr) // 查询连成功的地址是否在地址集中，如果不在，则不作处理
	if ka == nil {
		return
	}

	// ka.Timestamp is not updated here to avoid leaking information
	// about currently connected peers.
	// 如果地址在地址集中，则更新该地址的lastsuccess和lastattempt为当前时间点，且将试图重试次数attempts重置
	now := time.Now()
	ka.lastsuccess = now
	ka.lastattempt = now
	ka.attempts = 0

	// move to tried set, optionally evicting other addresses if neeed.
	if ka.tried {
		return
	}

	// ok, need to move it to tried.

	// remove from all new buckets.
	// record one of the buckets in question and call it the `first'
	addrKey := NetAddressKey(addr)
	oldBucket := -1
	for i := range a.addrNew {
		// we check for existence so we can record the first one
		if _, ok := a.addrNew[i][addrKey]; ok {
			delete(a.addrNew[i], addrKey) // 如果地址在NewBucket中，则将其从对应的Bucket中移除
			ka.refs--
			if oldBucket == -1 {
				oldBucket = i // 记录下了地址所处的NewBucket的索引号oldBucket，它将在后面用到
			}
		}
	}
	a.nNew--

	if oldBucket == -1 {
		// What? wasn't in a bucket after all.... Panic?
		return
	}

	bucket := a.getTriedBucket(ka.na) // 选择一个TriedBucket的索引号，用于将地址添加进对应的Bucket

	// Room in this tried bucket?
	if a.addrTried[bucket].Len() < triedBucketSize {
		ka.tried = true
		a.addrTried[bucket].PushBack(ka) //如果选择的TriedBucket未填满(容量为256)，则将地址添加到Bucket
		a.nTried++
		return
	}

	// No room, we have to evict something else.
	// 如果选择的TriedBucket已经填满，则调用pickTried()从其中选择一个地址，准备将其移动到NewBucket中以腾出空间
	entry := a.pickTried(bucket)
	rmka := entry.Value.(*KnownAddress)

	// First bucket it would have been put in.
	newBucket := a.getNewBucket(rmka.na, rmka.srcAddr)

	// If no room in the original bucket, we put it in a bucket we just
	// freed up a space in.
	if len(a.addrNew[newBucket]) >= newBucketSize {
		newBucket = oldBucket //如果欲移入的NewBucket已经满，则将选择的地址从TriedBucket中移入索引号为oldBucket的NewBucket中，即移入刚刚移除了addr的NewBucket中
	}

	// replace with ka in list.
	ka.tried = true
	entry.Value = ka //将连接成功的地址添加到选择的TriedBucket中，通过将listElement的Value直接更新为对应的ka来实现

	rmka.tried = false
	rmka.refs++

	// We don't touch a.nTried here since the number of tried stays the same
	// but we decemented new above, raise it again since we're putting
	// something back.
	a.nNew++

	rmkey := NetAddressKey(rmka.na)
	log.Tracef("Replacing %s with %s in tried", rmkey, addrKey)

	// We made sure there is space here just above.
	a.addrNew[newBucket][rmkey] = rmka // 将从TriedBucket中移出的地址移入选择的NewBucket中
}

// SetServices sets the services for the giiven address to the provided value.
func (a *AddrManager) SetServices(addr *wire.NetAddress, services wire.ServiceFlag) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	ka := a.find(addr)
	if ka == nil {
		return
	}

	// Update the services if needed.
	if ka.na.Services != services {
		// ka.na is immutable, so replace it.
		naCopy := *ka.na
		naCopy.Services = services
		ka.na = &naCopy
	}
}

// AddLocalAddress adds na to the list of known local addresses to advertise
// with the given priority.
func (a *AddrManager) AddLocalAddress(na *wire.NetAddress, priority AddressPriority) error {
	if !IsRoutable(na) {
		return fmt.Errorf("address %s is not routable", na.IP)
	}

	a.lamtx.Lock()
	defer a.lamtx.Unlock()

	key := NetAddressKey(na)
	la, ok := a.localAddresses[key]
	if !ok || la.score < priority {
		if ok {
			la.score = priority + 1
		} else {
			a.localAddresses[key] = &localAddress{
				na:    na,
				score: priority,
			}
		}
	}
	return nil
}

// getReachabilityFrom returns the relative reachability of the provided local
// address to the provided remote address.
func getReachabilityFrom(localAddr, remoteAddr *wire.NetAddress) int {
	const (
		Unreachable = 0
		Default     = iota
		Teredo
		Ipv6Weak
		Ipv4
		Ipv6Strong
		Private
	)

	if !IsRoutable(remoteAddr) {
		return Unreachable
	}

	if IsOnionCatTor(remoteAddr) {
		if IsOnionCatTor(localAddr) {
			return Private
		}

		if IsRoutable(localAddr) && IsIPv4(localAddr) {
			return Ipv4
		}

		return Default
	}

	if IsRFC4380(remoteAddr) {
		if !IsRoutable(localAddr) {
			return Default
		}

		if IsRFC4380(localAddr) {
			return Teredo
		}

		if IsIPv4(localAddr) {
			return Ipv4
		}

		return Ipv6Weak
	}

	if IsIPv4(remoteAddr) {
		if IsRoutable(localAddr) && IsIPv4(localAddr) {
			return Ipv4
		}
		return Unreachable
	}

	/* ipv6 */
	var tunnelled bool
	// Is our v6 is tunnelled?
	if IsRFC3964(localAddr) || IsRFC6052(localAddr) || IsRFC6145(localAddr) {
		tunnelled = true
	}

	if !IsRoutable(localAddr) {
		return Default
	}

	if IsRFC4380(localAddr) {
		return Teredo
	}

	if IsIPv4(localAddr) {
		return Ipv4
	}

	if tunnelled {
		// only prioritise ipv6 if we aren't tunnelling it.
		return Ipv6Weak
	}

	return Ipv6Strong
}

// GetBestLocalAddress returns the most appropriate local address to use
// for the given remote address.
func (a *AddrManager) GetBestLocalAddress(remoteAddr *wire.NetAddress) *wire.NetAddress {
	a.lamtx.Lock()
	defer a.lamtx.Unlock()

	bestreach := 0
	var bestscore AddressPriority
	var bestAddress *wire.NetAddress
	for _, la := range a.localAddresses {
		reach := getReachabilityFrom(la.na, remoteAddr)
		if reach > bestreach ||
			(reach == bestreach && la.score > bestscore) {
			bestreach = reach
			bestscore = la.score
			bestAddress = la.na
		}
	}
	if bestAddress != nil {
		log.Debugf("Suggesting address %s:%d for %s:%d", bestAddress.IP,
			bestAddress.Port, remoteAddr.IP, remoteAddr.Port)
	} else {
		log.Debugf("No worthy address for %s:%d", remoteAddr.IP,
			remoteAddr.Port)

		// Send something unroutable if nothing suitable.
		var ip net.IP
		if !IsIPv4(remoteAddr) && !IsOnionCatTor(remoteAddr) {
			ip = net.IPv6zero
		} else {
			ip = net.IPv4zero
		}
		services := wire.SFNodeNetwork | wire.SFNodeWitness | wire.SFNodeBloom
		bestAddress = wire.NewNetAddressIPPort(ip, 0, services)
	}

	return bestAddress
}

// New returns a new bitcoin address manager.
// Use Start to begin processing asynchronous address updates.
func New(dataDir string, lookupFunc func(string) ([]net.IP, error)) *AddrManager {
	am := AddrManager{
		peersFile:      filepath.Join(dataDir, "peers.json"),
		lookupFunc:     lookupFunc,
		rand:           rand.New(rand.NewSource(time.Now().UnixNano())),
		quit:           make(chan struct{}),
		localAddresses: make(map[string]*localAddress),
	}
	am.reset()
	return &am
}
