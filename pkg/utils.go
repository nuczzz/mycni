package pkg

import (
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

func AddArp(localVtepID int, remoteVtepIP net.IP, remoteVtepMac net.HardwareAddr) error {
	return netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    localVtepID,
		State:        netlink.NUD_PERMANENT,
		Type:         syscall.RTN_UNICAST,
		IP:           remoteVtepIP,
		HardwareAddr: remoteVtepMac,
	})
}

func DelArp(localVtepID int, remoteVtepIP net.IP, remoteVtepMac net.HardwareAddr) error {
	return netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    localVtepID,
		State:        netlink.NUD_PERMANENT,
		Type:         syscall.RTN_UNICAST,
		IP:           remoteVtepIP,
		HardwareAddr: remoteVtepMac,
	})
}

func AddFDB(localVtepID int, remoteHostIP net.IP, remoteVtepMac net.HardwareAddr) error {
	return netlink.NeighSet(&netlink.Neigh{
		LinkIndex:    localVtepID,
		Family:       syscall.AF_BRIDGE,
		State:        netlink.NUD_PERMANENT,
		Flags:        netlink.NTF_SELF,
		IP:           remoteHostIP,
		HardwareAddr: remoteVtepMac,
	})
}

func DelFDB(localVtepID int, remoteHostIP net.IP, remoteVtepMac net.HardwareAddr) error {
	return netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    localVtepID,
		Family:       syscall.AF_BRIDGE,
		State:        netlink.NUD_PERMANENT,
		Flags:        netlink.NTF_SELF,
		IP:           remoteHostIP,
		HardwareAddr: remoteVtepMac,
	})
}

func ReplaceRoute(localVtepID int, dst *net.IPNet, gateway net.IP) error {
	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: localVtepID,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       dst,
		Gw:        gateway,
		Flags:     syscall.RTNH_F_ONLINK,
	})
}

func DelRoute(localVtepID int, dst *net.IPNet, gateway net.IP) error {
	return netlink.RouteDel(&netlink.Route{
		LinkIndex: localVtepID,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       dst,
		Gw:        gateway,
		Flags:     syscall.RTNH_F_ONLINK,
	})
}
