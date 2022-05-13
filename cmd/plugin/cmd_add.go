package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/pkg/errors"
	"github.com/sanity-io/litter"
	"github.com/vishvananda/netlink"

	"mycni/cmd/plugin/log"
)

const (
	hostVethPairPrefix = "veth"
)

var (
	defaultHostVethMac, _ = net.ParseMAC("EE:EE:EE:EE:EE:EE")
	defaultPodGw          = net.IPv4(169, 254, 1, 1)
	defaultGwIPNet        = &net.IPNet{IP: defaultPodGw, Mask: net.CIDRMask(32, 32)}
	_, IPv4AllNet, _      = net.ParseCIDR("0.0.0.0/0")
	defaultRoutes         = []*net.IPNet{IPv4AllNet}
)

func cmdAdd(args *skel.CmdArgs) error {
	log.Debugf("cmdAdd containerID: %s", args.ContainerID)
	log.Debugf("cmdAdd netNs: %s", args.Netns)
	log.Debugf("cmdAdd ifName: %s", args.IfName)
	log.Debugf("cmdAdd args: %s", args.Args)
	log.Debugf("cmdAdd path: %s", args.Path)
	log.Debugf("cmdAdd stdin: %s", string(args.StdinData))

	// 解析数据
	conf, err := loadConfig(args.StdinData)
	if err != nil {
		log.Debugf("loadConfig error: %s", err.Error())
		return errors.Wrap(err, "loadConfig error")
	}
	log.Debugf("cmdAdd conf: %s", litter.Sdump(conf))

	cniArgs := parseArgs(args.Args)
	log.Debugf("cmdAdd cniArgs: %#v", cniArgs)

	var result *cniv1.Result

	// pod eth0配置ip
	ipamResult, err := applyIP(conf)
	if err != nil {
		log.Debugf("applyIP error: %s", err.Error())
		return errors.Wrapf(err, "applyIP error")
	}

	result, err = cniv1.GetResult(ipamResult)
	if err != nil {
		log.Debugf("GetResult error: %s", err.Error())
		return errors.Wrapf(err, "GetResult error")
	}

	hostVethName := vethNameForWorkload(cniArgs.namespace, cniArgs.podName)
	log.Debugf("hostVethName: %s", hostVethName)

	// 配置好veth pair
	if err = setupVethPair(args, result, hostVethName, defaultRoutes); err != nil {
		log.Debugf("setupVethPair error: %s", err.Error())
		return errors.Wrapf(err, "setupVethPair error")
	}

	// veth-x设置arp proxy
	if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", hostVethName), "1"); err != nil {
		log.Debugf("writeProcSys error: %s", err.Error())
		return fmt.Errorf("failed to set net.ipv4.conf.%s.proxy_arp=1: %s", hostVethName, err)
	}

	// up veth-x
	hostVeth, err := netlink.LinkByName(hostVethName)
	if err != nil {
		log.Debugf("get host veth error: %s", err.Error())
		return errors.Wrapf(err, "get host veth error")
	}
	if err = netlink.LinkSetUp(hostVeth); err != nil {
		log.Debugf("setup host veth error: %s", err.Error())
		return errors.Wrapf(err, "setup host veth error")
	}

	// 宿主机配置pod入方向路由
	for _, ipAddr := range result.IPs {
		route := netlink.Route{
			LinkIndex: hostVeth.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       &ipAddr.Address,
		}
		if err := netlink.RouteAdd(&route); err != nil {
			log.Debugf("host add route error: %s", err.Error())
			return errors.Wrapf(err, "host add route error")
		}
	}

	result.Interfaces = append(result.Interfaces, &cniv1.Interface{
		Name: hostVethName},
	)

	for _, ip := range result.IPs {
		ip.Gateway = nil
	}

	if err = result.Print(); err!= nil {
		log.Debugf("result Print error: %s", err.Error())
		return err
	}

	log.Debugf("cmdAdd: handle %s/%s success", cniArgs.namespace, cniArgs.podName)

	return nil
}

func vethNameForWorkload(namespace, podname string) string {
	// A SHA1 is always 20 bytes long, and so is sufficient for generating the
	// veth name and mac addr.
	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("%s.%s", namespace, podname)))
	return fmt.Sprintf("%s%s", hostVethPairPrefix, hex.EncodeToString(h.Sum(nil))[:11])
}

func setupVethPair(cmdArgs *skel.CmdArgs, result *cniv1.Result, hostVethName string, routes []*net.IPNet) error {
	// 如果同名的veth已经存在了，删除
	if oldHostVeth, err := netlink.LinkByName(hostVethName); err == nil {
		if err = netlink.LinkDel(oldHostVeth); err != nil {
			return errors.Wrapf(err, "failed to delete old hostVeth %v", hostVethName)
		}
	}

	var hasIPv4 bool
	// Note: 这个函数里的逻辑是在pod netns网络命名空间执行
	return ns.WithNetNSPath(cmdArgs.Netns, func(hostNS ns.NetNS) error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: cmdArgs.IfName,
				MTU:  1500,
				//NumTxQueues: d.queues,
				//NumRxQueues: d.queues,
			},
			PeerName: hostVethName,
		}

		// 创建veth pair
		if err := netlink.LinkAdd(veth); err != nil {
			return errors.Wrapf(err, "LinkAdd error")
		}

		hostVeth, err := netlink.LinkByName(hostVethName)
		if err != nil {
			err = fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
			return err
		}

		// Set the MAC address on the host side interface so the kernel does not
		// have to generate a persistent address which fails some times.
		if err = netlink.LinkSetHardwareAddr(hostVeth, defaultHostVethMac); err != nil {
			log.Debugf("failed to Set MAC of %q: %v. Using kernel generated MAC.", hostVethName, err)
		}

		// Figure out whether we have IPv4 addresses.
		for _, addr := range result.IPs {
			if addr.Address.IP.To4() != nil {
				hasIPv4 = true
				addr.Address.Mask = net.CIDRMask(32, 32)
			}
		}

		// up宿主机上的veth
		if err = netlink.LinkSetUp(hostVeth); err != nil {
			return fmt.Errorf("failed to set %q up: %w", hostVethName, err)
		}

		contVeth, err := netlink.LinkByName(cmdArgs.IfName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q: %v", cmdArgs.IfName, err)
		}

		// up pod网络veth
		if err = netlink.LinkSetUp(contVeth); err != nil {
			return fmt.Errorf("failed to set %q up: %w", cmdArgs.IfName, err)
		}

		if hasIPv4 {
			// Add a connected route to a dummy next hop so that a default route can be set
			// 添加路由： 169.254.1.1 dev eth0
			if err := netlink.RouteAdd(
				&netlink.Route{
					LinkIndex: contVeth.Attrs().Index,
					Scope:     netlink.SCOPE_LINK,
					Dst:       defaultGwIPNet,
				},
			); err != nil {
				return fmt.Errorf("failed to add route inside the container: %v", err)
			}

			// 添加 默认路由: 0.0.0.0/0 via 169.254.1.1 dev eth0
			for _, r := range routes {
				if r.IP.To4() == nil {
					continue
				}
				if err = ip.AddRoute(r, defaultPodGw, contVeth); err != nil {
					return fmt.Errorf("failed to add IPv4 route for %v via %v: %v", r, defaultPodGw, err)
				}
			}
		}

		// eth0配置ip
		for _, addr := range result.IPs {
			if err = netlink.AddrAdd(contVeth, &netlink.Addr{IPNet: &addr.Address}); err != nil {
				return fmt.Errorf("failed to add IP addr to %q: %v", contVeth, err)
			}
		}

		// hostVeth放入宿主机网络命名空间
		// 放入后需要重新up
		if err = netlink.LinkSetNsFd(hostVeth, int(hostNS.Fd())); err != nil {
			return fmt.Errorf("failed to move veth to host netns: %v", err)
		}

		return nil
	})
}

func applyIP(conf *MyCNIConfig) (types.Result, error) {
	ipNet, err := types.ParseCIDR(conf.IPAM.Subnet)
	if err != nil {
		return nil, errors.Wrapf(err, "ParseCIDR error")
	}

	startIP := net.ParseIP(conf.IPAM.RangeStart)
	if startIP == nil {
		return nil, errors.Errorf("range start %s error", conf.IPAM.RangeStart)
	}

	endIP := net.ParseIP(conf.IPAM.RangeEnd)
	if endIP == nil {
		return nil, errors.Errorf("range end %s error", conf.IPAM.RangeEnd)
	}

	ipamConf := allocator.Net{
		Name:       conf.Name,
		CNIVersion: conf.CNIVersion,
		IPAM: &allocator.IPAMConfig{
			Type: conf.IPAM.Type,
			Ranges: []allocator.RangeSet{
				{
					{
						Subnet:     types.IPNet(*ipNet),
						RangeStart: startIP,
						RangeEnd:   endIP,
					},
				},
			},
		},
	}
	ipamConfBytes, err := json.Marshal(ipamConf)
	if err != nil {
		return nil, errors.Wrapf(err, "marshal ipam conf error")
	}
	log.Debugf("ipamConfBytes: %s", string(ipamConfBytes))

	return ipam.ExecAdd(conf.IPAM.Type, ipamConfBytes)
}