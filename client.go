package gokatran

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/math-chao/go-katran/katran"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

const (
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
	NO_SPORT    = 1
	NO_LRU      = 2
	QUIC_VIP    = 4
	DPORT_HASH  = 8
	LOCAL_VIP   = 32

	LOCAL_REAL = 2
)

const (
	ADD_VIP = iota
	DEL_VIP
	MODIFY_VIP
)

var (
	vipFlagTranslationTable = map[string]int64{
		"NO_SPORT":   NO_SPORT,
		"NO_LRU":     NO_LRU,
		"QUIC_VIP":   QUIC_VIP,
		"DPORT_HASH": DPORT_HASH,
		"LOCAL_VIP":  LOCAL_VIP,
	}
	realFlagTranslationTable = map[string]int32{
		"LOCAL_REAL": LOCAL_REAL,
	}
)

// func checkError(err error) {
// 	if err != nil {
// 		log.Fatalf("Error: %v\n", err)
// 	}
// }

func NewClient(serverAddr string, opts ...grpc.DialOption) (*Client, error) {
	client := &Client{}
	// opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.NewClient(serverAddr, opts...)
	// conn, err := grpc.Dial(serverAddr, opts...)
	if err != nil {
		return nil, errors.WithMessage(err, "KatranClient Init failed")
	}
	client.client = katran.NewKatranServiceClient(conn)
	return client, nil
}

type Client struct {
	client katran.KatranServiceClient
}

// func (kc *Client) Init(serverAddr string) error {
// 	var opts []grpc.DialOption
// 	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
// 	conn, err := grpc.NewClient(serverAddr, opts...)
// 	// conn, err := grpc.Dial(serverAddr, opts...)
// 	if err != nil {
// 		return errors.WithMessage(err, "KatranClient Init failed")
// 	}
// 	kc.client = katran.NewKatranServiceClient(conn)
// 	return nil
// }

func (kc *Client) ChangeMac(ctx context.Context, mac string) error {
	newMac := katran.Mac{Mac: mac}
	res, err := kc.client.ChangeMac(ctx, &newMac)
	if err != nil {
		return errors.WithMessage(err, "KatranClient ChangeMac failed")
	}

	if !res.Success {
		log.Print("Mac was not changed")
		return errors.Errorf("KatranClient ChangeMac not success")
	}

	return nil

	// checkError(err)
	// if res.Success {
	// 	log.Print("Mac address changed!")
	// } else {
	// 	log.Print("Mac was not changed")
	// }
}

func (kc *Client) GetMac(ctx context.Context) (string, error) {
	mac, err := kc.client.GetMac(ctx, &katran.Empty{})
	if err != nil {
		return "", errors.WithMessage(err, "KatranClient GetMac Failed")
	}
	return mac.GetMac(), nil
	// checkError(err)
	// log.Printf("Mac address is %v\n", mac.GetMac())
}

func parseToVip(addr string, proto int) (*katran.Vip, error) {
	vip := &katran.Vip{}
	vip.Protocol = int32(proto)
	if strings.Index(addr, "[") >= 0 {
		// v6 address. format [<addr>]:<port>
		v6re := regexp.MustCompile(`\[(.*?)\]:(.*)`)
		addr_port := v6re.FindStringSubmatch(addr)
		if addr_port == nil {
			return nil, errors.Errorf("ParseToVip for addr %s failed, invalid v6 address", addr)
			// log.Fatalf("invalid v6 address %v\n", addr)
		}

		vip.Address = addr_port[1]
		port, err := strconv.ParseInt(addr_port[2], 10, 32)
		if err != nil {
			return nil, errors.Wrapf(err, "ParseToVip for addr %s failed, port is invalid", addr)
		}

		vip.Port = int32(port)
		return vip, nil
	}
	// checkError(err)
	// v4 address. format <addr>:<port>
	addr_port := strings.Split(addr, ":")
	if len(addr_port) != 2 {
		return nil, errors.Errorf("ParseToVip for addr %s failed, invalid v4 address", addr)
		// log.Fatalf("incorrect v4 address: %v\n", addr)
	}

	vip.Address = addr_port[0]
	port, err := strconv.ParseInt(addr_port[1], 10, 32)
	if err != nil {
		return nil, errors.Wrapf(err, "ParseToVip for addr %s failed, port is invalid", addr)
	}
	vip.Port = int32(port)
	// checkError(err)
	return vip, nil
}

func parseToReal(addr string, weight int64, flags int32) *katran.Real {
	var real katran.Real
	real.Address = addr
	real.Weight = int32(weight)
	real.Flags = flags
	return &real
}

func parseToQuicReal(mapping string) (*katran.QuicReal, error) {
	addr_id := strings.Split(mapping, "=")
	if len(addr_id) != 2 {
		return nil, errors.Errorf("ParseToQuicReal for %s failed, quic mapping must be in <addr>=<id> format", mapping)
	}

	id, err := strconv.ParseInt(addr_id[1], 10, 64)
	if err != nil {
		return nil, errors.Wrapf(err, "ParseToQuicReal for %s failed", mapping)
	}

	// checkError(err)
	var qr katran.QuicReal
	qr.Address = addr_id[0]
	qr.Id = int32(id)
	return &qr, nil
}

func (kc *Client) AddOrModifyService(ctx context.Context, addr string, flagsString string, proto int, modify bool, setFlags bool) error {
	log.Printf("Adding service: %v %v\n", addr, proto)
	vip, err := parseToVip(addr, proto)
	if err != nil {
		return errors.WithMessage(err, "AddOrModifyService failed")
	}

	var flags int64
	var exists bool
	if flagsString != "" {
		if flags, exists = vipFlagTranslationTable[flagsString]; !exists {
			// log.Printf("unrecognized flag: %v\n", flagsString)
			return errors.Errorf("AddOrModifyService failed, unrecognized flag:%v", flagsString)
			// return
		}
	}
	action := ADD_VIP
	if modify {
		action = MODIFY_VIP
	}
	return kc.UpdateService(ctx, vip, flags, action, setFlags)

	// if modify {
	// 	return kc.UpdateService(vip, flags, MODIFY_VIP, setFlags)
	// } else {
	// 	return kc.UpdateService(vip, flags, ADD_VIP, setFlags)
	// }
}

func (kc *Client) DelService(ctx context.Context, addr string, proto int) error {
	log.Printf("Deleting service: %v %v\n", addr, proto)
	vip, err := parseToVip(addr, proto)
	if err != nil {
		return errors.WithMessagef(err, "DelService %d:%s failed", proto, addr)
	}
	return kc.UpdateService(ctx, vip, 0, DEL_VIP, false)
}

func (kc *Client) UpdateReal(ctx context.Context, addr string, flags int32, setFlags bool) error {
	var rMeta katran.RealMeta
	rMeta.Address = addr
	rMeta.Flags = flags
	rMeta.SetFlag = setFlags
	ok, err := kc.client.ModifyReal(ctx, &rMeta)
	if err != nil {
		return errors.Wrapf(err, "UpdateReal for addr:%s flags:%d setFlags:%v failed", addr, flags, setFlags)
	}

	if !ok.Success {
		return errors.Errorf("UpdateReal for addr:%s flags:%d setFlags:%v failed, modify not success", addr, flags, setFlags)
	}

	log.Printf("Real modified\n")
	// checkError(err)
	// if ok.Success {
	// 	log.Printf("Real modified\n")
	// }
	return nil
}

func (kc *Client) UpdateService(ctx context.Context, vip *katran.Vip, flags int64, action int, setFlags bool) error {
	var vMeta katran.VipMeta
	var ok *katran.Bool
	var err error
	vMeta.Vip = vip
	vMeta.Flags = flags
	vMeta.SetFlag = setFlags
	switch action {
	case MODIFY_VIP:
		ok, err = kc.client.ModifyVip(ctx, &vMeta)
		break
	case ADD_VIP:
		ok, err = kc.client.AddVip(ctx, &vMeta)
		break
	case DEL_VIP:
		ok, err = kc.client.DelVip(ctx, vip)
		break
	default:
		break
	}

	if err != nil {
		return errors.WithMessagef(err, "UpdateService failed")
	}
	// checkError(err)
	if !ok.Success {
		return errors.Errorf("UpdateService failed, not success")
	}

	log.Printf("Vip modified\n")
	return nil
}

func (kc *Client) UpdateServerForVip(ctx context.Context, vipAddr string, proto int, realAddr string, weight int64, realFlags string, delete bool) error {
	vip, err := parseToVip(vipAddr, proto)
	if err != nil {
		return errors.WithMessage(err, "UpdateServerForVip failed")
	}

	var flags int32
	var exists bool
	if realFlags != "" {
		if flags, exists = realFlagTranslationTable[realFlags]; !exists {
			return errors.Errorf("UpdateServerForVip failed, unrecognized flag:%v", realFlags)
			// log.Printf("unrecognized flag: %v\n", realFlags)
			// return
		}
	}
	real := parseToReal(realAddr, weight, flags)
	var action katran.Action
	if delete {
		action = katran.Action_DEL
	} else {
		action = katran.Action_ADD
	}
	var reals katran.Reals
	reals.Reals = append(reals.Reals, real)
	return kc.ModifyRealsForVip(ctx, vip, &reals, action)
}

func (kc *Client) ModifyRealsForVip(ctx context.Context, vip *katran.Vip, reals *katran.Reals, action katran.Action) error {
	var mReals katran.ModifiedRealsForVip
	mReals.Vip = vip
	mReals.Real = reals
	mReals.Action = action
	ok, err := kc.client.ModifyRealsForVip(ctx, &mReals)
	if err != nil {
		return errors.Wrapf(err, "ModifyRealsForVip failed")
	}

	// checkError(err)
	if !ok.Success {
		return errors.Errorf("ModifyRealsForVip failed, not success")
	}
	log.Printf("Reals modified\n")
	return nil
}

func (kc *Client) ModifyQuicMappings(ctx context.Context, mapping string, delete bool) error {
	var action katran.Action
	if delete {
		action = katran.Action_DEL
	} else {
		action = katran.Action_ADD
	}
	qr, err := parseToQuicReal(mapping)
	if err != nil {
		return errors.WithMessage(err, "ModifyQuicMappings failed")
	}

	var qrs katran.QuicReals
	qrs.Qreals = append(qrs.Qreals, qr)
	var mqr katran.ModifiedQuicReals
	mqr.Reals = &qrs
	mqr.Action = action
	ok, err := kc.client.ModifyQuicRealsMapping(ctx, &mqr)
	// checkError(err)
	// if ok.Success {
	// 	log.Printf("Quic mapping modified\n")
	// }
	if err != nil {
		return errors.Wrapf(err, "ModifyQuicRealsMapping failed")
	}

	// checkError(err)
	if !ok.Success {
		return errors.Errorf("ModifyQuicRealsMapping failed, not success")
	}
	log.Printf("Quic mapping modified\n")
	return nil
}

func (kc *Client) GetAllVips(ctx context.Context) (*katran.Vips, error) {
	vips, err := kc.client.GetAllVips(ctx, &katran.Empty{})
	if err != nil {
		return nil, errors.Wrapf(err, "GetAllVips failed")
	}
	// checkError(err)
	return vips, nil
}

func (kc *Client) GetAllHcs(ctx context.Context) (*katran.HcMap, error) {
	hcs, err := kc.client.GetHealthcheckersDst(ctx, &katran.Empty{})
	if err != nil {
		return nil, errors.Wrap(err, "GetAllHcs failed")
	}
	// checkError(err)
	return hcs, nil
}

func (kc *Client) GetRealsForVip(ctx context.Context, vip *katran.Vip) (*katran.Reals, error) {
	reals, err := kc.client.GetRealsForVip(ctx, vip)
	if err != nil {
		return nil, errors.Wrap(err, "GetRealsForVip failed")
	}
	// checkError(err)
	return reals, nil
}

func (kc *Client) GetVipFlags(ctx context.Context, vip *katran.Vip) (uint64, error) {
	flags, err := kc.client.GetVipFlags(ctx, vip)
	if err != nil {
		return 0, errors.Wrap(err, "GetVipFlags failed")
	}
	// checkError(err)
	return flags.Flags, nil
}

func parseVipFlags(flags uint64) string {
	flags_str := ""
	if flags&uint64(NO_SPORT) > 0 {
		flags_str += " NO_SPORT "
	}
	if flags&uint64(NO_LRU) > 0 {
		flags_str += " NO_LRU "
	}
	if flags&uint64(QUIC_VIP) > 0 {
		flags_str += " QUIC_VIP "
	}
	if flags&uint64(DPORT_HASH) > 0 {
		flags_str += " DPORT_HASH "
	}
	if flags&uint64(LOCAL_VIP) > 0 {
		flags_str += " LOCAL_VIP "
	}
	return flags_str
}

func parseRealFlags(flags int32) string {
	if flags < 0 {
		log.Fatalf("invalid real flags passed: %v\n", flags)
	}
	flags_str := ""
	if flags&LOCAL_REAL > 0 {
		flags_str += " LOCAL_REAL "
	}
	return flags_str
}

func (kc *Client) ListVipAndReals(ctx context.Context, vip *katran.Vip) {
	reals, err := kc.GetRealsForVip(ctx, vip)
	if err != nil {
		log.Println(err)
		return
	}

	proto := ""
	if vip.Protocol == IPPROTO_TCP {
		proto = "tcp"
	} else {
		proto = "udp"
	}
	fmt.Printf("VIP: %20v Port: %6v Protocol: %v\n",
		vip.Address,
		vip.Port,
		proto)
	flags, err := kc.GetVipFlags(ctx, vip)
	if err != nil {
		log.Println(err)
	}

	fmt.Printf("Vip's flags: %v\n", parseVipFlags(flags))
	for _, real := range reals.Reals {
		fmt.Printf("%-20v weight: %v flags: %v\n",
			" ->"+real.Address,
			real.Weight, parseRealFlags(real.Flags))
	}
}

func (kc *Client) List(ctx context.Context, addr string, proto int) {
	vips, err := kc.GetAllVips(ctx)
	if err != nil {
		log.Println(err)
	}

	log.Printf("vips len %v", len(vips.Vips))
	for _, vip := range vips.Vips {
		kc.ListVipAndReals(ctx, vip)
	}
}

func (kc *Client) ClearAll(ctx context.Context) error {
	fmt.Println("Deleting Vips")
	vips, err := kc.GetAllVips(ctx)
	if err != nil {
		return errors.WithMessage(err, "ClearAll failed")
		// log.Println(err)
	}

	for _, vip := range vips.Vips {
		ok, err := kc.client.DelVip(context.Background(), vip)
		if err != nil {
			return errors.Wrapf(err, "ClearAll del vip %s failed", vip.GetAddress())
		}
		if !ok.Success {
			return errors.Errorf("ClearAll del vip %s failed, not success", vip.GetAddress())
		}
		// if err != nil || !ok.Success {
		// 	fmt.Printf("error while deleting vip: %v", vip.Address)
		// }
	}

	fmt.Println("Deleting Healthchecks")
	hcs, err := kc.GetAllHcs(ctx)
	if err != nil {
		log.Println(err)
	}

	var Somark katran.Somark
	for somark, dst := range hcs.Healthchecks {
		Somark.Somark = uint32(somark)
		ok, err := kc.client.DelHealthcheckerDst(ctx, &Somark)
		// if err != nil || !ok.Success {
		// 	fmt.Printf("error while deleting hc w/ somark: %v", somark)
		// }
		if err != nil {
			return errors.Wrapf(err, "ClearAll del hc %s failed", dst)
		}
		if !ok.Success {
			return errors.Errorf("ClearAll del hc %s failed, not success", dst)
		}
	}
	return nil
}

func (kc *Client) ListQm(ctx context.Context) {
	fmt.Printf("printing address to quic's connection id mapping\n")
	qreals, err := kc.client.GetQuicRealsMapping(
		ctx, &katran.Empty{})
	if err != nil {
		log.Println(err)
	}
	// checkError(err)

	for _, qr := range qreals.Qreals {
		fmt.Printf("real: %20v = connection id: %6v\n",
			qr.Address,
			qr.Id)
	}
}

func (kc *Client) AddHc(ctx context.Context, addr string, somark uint64) {
	var hc katran.Healthcheck
	hc.Somark = uint32(somark)
	hc.Address = addr
	ok, err := kc.client.AddHealthcheckerDst(ctx, &hc)
	if err != nil {
		log.Println(err)
	}

	// checkError(err)
	if !ok.Success {
		fmt.Printf("error while add hc w/ somark: %v and addr %v", somark, addr)
	}
}

func (kc *Client) DelHc(ctx context.Context, somark uint64) error {
	var sm katran.Somark
	sm.Somark = uint32(somark)
	ok, err := kc.client.DelHealthcheckerDst(ctx, &sm)
	if err != nil {
		return errors.Wrapf(err, "DelHc with mark %d failed", somark)
	}

	if !ok.Success {
		return errors.Errorf("DelHc with mark %d failed, not success", somark)
	}

	// checkError(err)
	// if !ok.Success {
	// 	fmt.Printf("error while deleting hc w/ somark: %v", somark)
	// }
	return nil
}

func (kc *Client) ListHc(ctx context.Context) {
	hcs, err := kc.GetAllHcs(ctx)
	if err != nil {
		log.Println(err)
		return
	}

	for somark, addr := range hcs.Healthchecks {
		fmt.Printf("somark: %10v addr: %10v\n",
			somark,
			addr)
	}
}

func (kc *Client) ShowSumStats(ctx context.Context) {
	oldPkts := uint64(0)
	oldBytes := uint64(0)
	vips, err := kc.GetAllVips(ctx)
	if err != nil {
		log.Println(err)
		return
	}

	for true {
		pkts := uint64(0)
		bytes := uint64(0)
		for _, vip := range vips.Vips {
			stats, err := kc.client.GetStatsForVip(ctx, vip)
			if err != nil {
				continue
			}
			pkts += stats.V1
			bytes += stats.V2
		}
		diffPkts := pkts - oldPkts
		diffBytes := bytes - oldBytes
		fmt.Printf("summary: %v pkts/sec %v bytes/sec\n", diffPkts, diffBytes)
		oldPkts = pkts
		oldBytes = bytes
		time.Sleep(1 * time.Second)
	}
}

func (kc *Client) ShowLruStats(ctx context.Context) {
	oldTotalPkts := uint64(0)
	oldMiss := uint64(0)
	oldTcpMiss := uint64(0)
	oldTcpNonSynMiss := uint64(0)
	oldFallbackLru := uint64(0)
	for true {
		lruMiss := float64(0)
		tcpMiss := float64(0)
		tcpNonSynMiss := float64(0)
		udpMiss := float64(0)
		lruHit := float64(0)
		stats, err := kc.client.GetLruStats(
			ctx, &katran.Empty{})
		if err != nil {
			continue
		}
		missStats, err := kc.client.GetLruMissStats(
			ctx, &katran.Empty{})
		if err != nil {
			continue
		}
		fallbackStats, err := kc.client.GetLruFallbackStats(
			ctx, &katran.Empty{})
		if err != nil {
			continue
		}
		diffTotal := stats.V1 - oldTotalPkts
		diffMiss := stats.V2 - oldMiss
		diffTcpMiss := missStats.V1 - oldTcpMiss
		diffTcpNonSynMiss := missStats.V2 - oldTcpNonSynMiss
		diffFallbackLru := fallbackStats.V1 - oldFallbackLru
		if diffTotal != 0 {
			lruMiss = float64(diffMiss) / float64(diffTotal)
			tcpMiss = float64(diffTcpMiss) / float64(diffTotal)
			tcpNonSynMiss = float64(diffTcpNonSynMiss) / float64(diffTotal)
			udpMiss = 1 - (tcpMiss + tcpNonSynMiss)
			lruHit = 1 - lruMiss
		}
		fmt.Printf("summary: %d pkts/sec. lru hit: %.2f%% lru miss: %.2f%% ",
			diffTotal, lruHit*100, lruMiss*100)
		fmt.Printf("(tcp syn: %.2f%% tcp non-syn: %.2f%% udp: %.2f%%)", tcpMiss,
			tcpNonSynMiss, udpMiss)
		fmt.Printf(" fallback lru hit: %d pkts/sec\n", diffFallbackLru)
		oldTotalPkts = stats.V1
		oldMiss = stats.V2
		oldTcpMiss = missStats.V1
		oldTcpNonSynMiss = missStats.V2
		oldFallbackLru = fallbackStats.V1
		time.Sleep(1 * time.Second)
	}
}

func (kc *Client) ShowPerVipStats(ctx context.Context) {
	vips, err := kc.GetAllVips(ctx)
	if err != nil {
		log.Println(err)
		return
	}

	statsMap := make(map[string]uint64)
	for _, vip := range vips.Vips {
		key := strings.Join([]string{
			vip.Address, strconv.Itoa(int(vip.Port)),
			strconv.Itoa(int(vip.Protocol))}, ":")
		statsMap[key+":pkts"] = 0
		statsMap[key+":bytes"] = 0
	}
	for true {
		for _, vip := range vips.Vips {
			key := strings.Join([]string{
				vip.Address, strconv.Itoa(int(vip.Port)),
				strconv.Itoa(int(vip.Protocol))}, ":")
			stats, err := kc.client.GetStatsForVip(ctx, vip)
			if err != nil {
				continue
			}
			diffPkts := stats.V1 - statsMap[key+":pkts"]
			diffBytes := stats.V2 - statsMap[key+":bytes"]
			fmt.Printf("vip: %16s : %8d pkts/sec %8d bytes/sec\n",
				key, diffPkts, diffBytes)
			statsMap[key+":pkts"] = stats.V1
			statsMap[key+":bytes"] = stats.V2
		}
		time.Sleep(1 * time.Second)
	}
}

func (kc *Client) ShowIcmpStats(ctx context.Context) {
	oldIcmpV4 := uint64(0)
	oldIcmpV6 := uint64(0)
	for true {
		icmps, err := kc.client.GetIcmpTooBigStats(ctx, &katran.Empty{})
		if err != nil {
			log.Println(err)
			return
		}
		// checkError(err)
		diffIcmpV4 := icmps.V1 - oldIcmpV4
		diffIcmpV6 := icmps.V2 - oldIcmpV6
		fmt.Printf(
			"ICMP \"packet too big\": v4 %v pkts/sec v6: %v pkts/sec\n",
			diffIcmpV4, diffIcmpV6)
		oldIcmpV4 = icmps.V1
		oldIcmpV6 = icmps.V2
		time.Sleep(1 * time.Second)
	}
}
