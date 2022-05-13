package pkg

import (
	"crypto/rand"
	"net"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

func newHardwareAddr() (net.HardwareAddr, error) {
	hardwareAddr := make(net.HardwareAddr, 6)
	if _, err := rand.Read(hardwareAddr); err != nil {
		return nil, errors.Wrap(err, "read hardware addr error")
	}

	// ensure that address is locally administered and unicast
	hardwareAddr[0] = (hardwareAddr[0] & 0xfe) | 0x02

	return hardwareAddr, nil
}

func getIfaceAddr(iface *net.Interface) ([]netlink.Addr, error) {
	return netlink.AddrList(&netlink.Device{
		LinkAttrs: netlink.LinkAttrs{
			Index: iface.Index,
		},
	}, syscall.AF_INET)
}

func getDefaultGatewayInterface() (*net.Interface, error) {
	routes, err := netlink.RouteList(nil, syscall.AF_INET)
	if err != nil {
		return nil, errors.Wrap(err, "RouteList error")
	}

	for _, route := range routes {
		if route.Dst == nil || route.Dst.String() == "0.0.0.0/0" {
			if route.LinkIndex <= 0 {
				return nil, errors.Errorf("found default route but could not determine interface")
			}
			return net.InterfaceByIndex(route.LinkIndex)
		}
	}

	return nil, errors.Errorf("unable to find default route")
}

const (
	vxlanName     = "vxlan.1"
	vxlanVNI      = 1
	vxlanPort     = 8472
	encapOverhead = 50
)

func NewVxlanDevice() (*netlink.Vxlan, error) {
	hardwareAddr, err := newHardwareAddr()
	if err != nil {
		return nil, errors.Wrap(err, "newHardwareAddr error")
	}

	gateway, err := getDefaultGatewayInterface()
	if err != nil {
		return nil, errors.Wrap(err, "getDefaultGatewayInterface error")
	}

	localHostAddrs, err := getIfaceAddr(gateway)
	if err != nil {
		return nil, errors.Wrap(err, "getIfaceAddr error")
	}

	if len(localHostAddrs) == 0 {
		return nil, errors.Errorf("length of local host addrs is 0")
	}

	return ensureVxlan(&netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:         vxlanName,
			HardwareAddr: hardwareAddr,
			MTU:          gateway.MTU - encapOverhead,
		},
		VxlanId:      vxlanVNI,
		VtepDevIndex: gateway.Index,
		SrcAddr:      localHostAddrs[0].IP,
		Port:         vxlanPort,
	})
}

func ensureVxlan(vxlan *netlink.Vxlan) (*netlink.Vxlan, error) {
	link, err := netlink.LinkByName(vxlan.Name)
	if err == nil {
		v, ok := link.(*netlink.Vxlan)
		if !ok {
			return nil, errors.Errorf("link %s already exists but not vxlan device", vxlan.Name)
		}

		klog.Infof("vxlan device %s already exists", vxlan.Name)
		return v, nil
	}

	if !strings.Contains(err.Error(), "Link not found") {
		return nil, errors.Wrapf(err, "get link %s error", vxlan.Name)
	}

	klog.Infof("vxlan device %s not found, and create it", vxlan.Name)

	if err = netlink.LinkAdd(vxlan); err != nil {
		return nil, errors.Wrap(err, "LinkAdd error")
	}

	link, err = netlink.LinkByName(vxlan.Name)
	if err != nil {
		return nil, errors.Wrap(err, "LinkByName error")
	}

	return link.(*netlink.Vxlan), nil
}
