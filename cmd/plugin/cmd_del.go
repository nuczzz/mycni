package main

import (
	"encoding/json"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/pkg/errors"
	"github.com/sanity-io/litter"

	"mycni/cmd/plugin/log"
)

func cmdDel(args *skel.CmdArgs) error {
	log.Debugf("cmdDel containerID: %s", args.ContainerID)
	log.Debugf("cmdDel netNs: %s", args.Netns)
	log.Debugf("cmdDel ifName: %s", args.IfName)
	log.Debugf("cmdDel args: %s", args.Args)
	log.Debugf("cmdDel path: %s", args.Path)
	log.Debugf("cmdDel stdin: %s", string(args.StdinData))

	// 解析数据
	conf, err := loadConfig(args.StdinData)
	if err != nil {
		log.Debugf("loadConfig error: %s", err.Error())
		return errors.Wrap(err, "loadConfig error")
	}
	log.Debugf("cmdDel conf: %s", litter.Sdump(conf))

	// 释放ip
	if err = releaseIP(conf); err != nil {
		log.Debugf("releaseIP error: %s", err.Error())
		return errors.Wrapf(err, "releaseIP error")
	}

	cniArgs := parseArgs(args.Args)
	log.Debugf("cmdDel cniArgs: %#v", cniArgs)

	hostVethName := vethNameForWorkload(cniArgs.namespace, cniArgs.podName)
	log.Debugf("hostVethName: %s", hostVethName)

	// 删除veth pair
	if err = ip.DelLinkByName(hostVethName); err != nil {
		log.Debugf("DelLinkByName error: %s, but return nil", err.Error())
	}

	log.Debugf("cmdDel: handle %s/%s success", cniArgs.namespace, cniArgs.podName)

	return nil
}

func releaseIP(conf *MyCNIConfig) error {
	ipNet, err := types.ParseCIDR(conf.IPAM.Subnet)
	if err != nil {
		return errors.Wrapf(err, "ParseCIDR error")
	}

	var startIP, endIP net.IP
	if conf.IPAM.RangeStart != "" {
		startIP = net.ParseIP(conf.IPAM.RangeStart)
		if startIP == nil {
			return errors.Errorf("range start %s error", conf.IPAM.RangeStart)
		}
	}
	if conf.IPAM.RangeEnd != "" {
		endIP = net.ParseIP(conf.IPAM.RangeEnd)
		if endIP == nil {
			return errors.Errorf("range end %s error", conf.IPAM.RangeEnd)
		}
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
		return errors.Wrapf(err, "marshal ipam conf error")
	}
	log.Debugf("ipamConfBytes: %s", string(ipamConfBytes))

	return ipam.ExecDel(conf.IPAM.Type, ipamConfBytes)
}
