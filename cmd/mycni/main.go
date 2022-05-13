package main

import (
	"net"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	coreV1 "k8s.io/api/core/v1"
	"k8s.io/component-base/cli/flag"
	"k8s.io/klog/v2"
	"k8s.io/sample-controller/pkg/signals"

	"mycni/pkg"
)

const (
	mycniVtepMacAnnotationKey = "mycni.vtep.mac"
	mycniHostIPAnnotationKey  = "mycni.host.ip"
)

func main() {
	flag.InitFlags()
	klog.Infof("prepare to start mycni")

	stopCh := signals.SetupSignalHandler()

	if err := pkg.InitK8sClient(stopCh); err != nil {
		klog.Fatalf("InitK8sClient error: %s", err.Error())
	}
	klog.Infof("InitK8sClient success")

	node, err := pkg.GetCurrentNode()
	if err != nil {
		klog.Fatalf("GetCurrentNode error: %s", err.Error())
	}
	if node.Spec.PodCIDR == "" {
		klog.Fatalf("node %s spec.podCidr is not set", node.Name)
	}
	klog.Infof("GetCurrentNode success")

	vxlanDevice, err := initVxlanDevice(node.Spec.PodCIDR)
	if err != nil {
		klog.Fatalf("initVxlanDevice error: %s", err.Error())
	}
	klog.Infof("initVxlanDevice success")

	if err = uploadVxlanDeviceInfo(node, vxlanDevice); err != nil {
		klog.Fatalf("uploadVxlanDeviceInfo error: %s", err.Error())
	}
	klog.Infof("uploadVxlanDeviceInfo success")

	pkg.InitController(filterNode(node.Name), nodeAddFn(vxlanDevice), nodeDelFn(vxlanDevice), nodeUpdateFn(vxlanDevice))
	klog.Infof("InitController success")

	klog.Infof("mycni start success")
	<-stopCh
}

func initVxlanDevice(podCidr string) (*netlink.Vxlan, error) {
	// 先创建vxlan设备
	vxlanLink, err := pkg.NewVxlanDevice()
	if err != nil {
		return nil, errors.Wrap(err, "NewVXLANDevice error")
	}

	// podCidr格式：10.244.1.0/24
	_, cidr, err := net.ParseCIDR(podCidr)
	if err != nil {
		return nil, errors.Wrap(err, "ParseCIDR error")
	}

	existingAddrs, err := netlink.AddrList(vxlanLink, netlink.FAMILY_V4)
	if err != nil {
		return nil, errors.Wrapf(err, "AddrList error")
	}
	if len(existingAddrs) == 0 {
		// 给vxlan设备配置IP
		// 确保vxlan设备掩码是32位，防止自动出来一条广播路由
		klog.Infof("config vxlan device %s ip: %s", vxlanLink.Name, cidr.IP)
		if err = netlink.AddrAdd(vxlanLink, &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   cidr.IP,
				Mask: net.IPv4Mask(255, 255, 255, 255),
			},
		}); err != nil {
			return nil, errors.Wrap(err, "AddrAdd error")
		}
	}

	// up vxlan设备
	if err = netlink.LinkSetUp(vxlanLink); err != nil {
		return nil, errors.Wrap(err, "LinkSetUp error")
	}

	return vxlanLink, nil
}

func uploadVxlanDeviceInfo(node *coreV1.Node, vxlanDevice *netlink.Vxlan) error {
	newNode := node.DeepCopy()
	newNode.Annotations[mycniVtepMacAnnotationKey] = vxlanDevice.HardwareAddr.String()
	newNode.Annotations[mycniHostIPAnnotationKey] = vxlanDevice.SrcAddr.String()

	klog.Infof("mac: %s", vxlanDevice.HardwareAddr.String())
	klog.Infof("host ip: %s", vxlanDevice.SrcAddr.String())

	return pkg.PatchNode(node, newNode)
}

func filterNode(nodeName string) func(obj interface{}) bool {
	return func(obj interface{}) bool {
		node, ok := obj.(*coreV1.Node)
		if !ok {
			return false
		}

		// 不处理自己这个节点
		if nodeName == node.Name {
			return false
		}

		return true
	}
}

func handlerAddOrUpdate(vxlanDevice *netlink.Vxlan, obj interface{}) error {
	// filter函数已对类型做了过滤，这里直接断言ok
	node := obj.(*coreV1.Node)
	_, ipnet, err := net.ParseCIDR(node.Spec.PodCIDR)
	if err != nil {
		return errors.Wrapf(err, "ParseCIDR %s error", node.Spec.PodCIDR)
	}

	vtepMacStr := node.Annotations[mycniVtepMacAnnotationKey]
	if vtepMacStr == "" {
		return errors.Wrapf(err, "node %s vtep mac is null", node.Name)
	}
	vtepMac, err := net.ParseMAC(vtepMacStr)
	if err != nil {
		return errors.Wrapf(err, "ParseMAC %s error", vtepMacStr)
	}

	hostIP := net.ParseIP(node.Annotations[mycniHostIPAnnotationKey])
	if hostIP == nil {
		return errors.Errorf("hostIP is nil")
	}

	if err = pkg.AddArp(vxlanDevice.Index, ipnet.IP, vtepMac); err != nil {
		return errors.Wrapf(err, "node %s add event AddARP error: %s", node.Name, err.Error())
	}
	klog.Infof("AddARP: arp -i %s -s %s %s", vxlanDevice.Name, ipnet.IP.String(), vtepMac.String())

	if err = pkg.AddFDB(vxlanDevice.Index, hostIP, vtepMac); err != nil {
		return errors.Wrapf(err, "node %s add event AddFDB error: %s", node.Name, err.Error())
	}
	klog.Infof("AddFDB: bridge fdb append %s dev %s dst %s", vtepMac.String(), vxlanDevice.Name, hostIP)

	if err = pkg.ReplaceRoute(vxlanDevice.Index, ipnet, ipnet.IP); err != nil {
		return errors.Wrapf(err, "node %s add event ReplaceRoute error: %s", node.Name, err.Error())
	}
	klog.Infof("ReplaceRoute: ip route add %s via %s dev %s onlink", ipnet.String(), ipnet.IP, vxlanDevice.Name)

	return nil
}

func nodeAddFn(vxlanDevice *netlink.Vxlan) func(obj interface{}) {
	return func(obj interface{}) {
		node := obj.(*coreV1.Node)
		klog.Infof("node add event: %s", node.Name)

		if err := handlerAddOrUpdate(vxlanDevice, obj); err != nil {
			klog.Errorf("handlerAddOrUpdate error: %s", err.Error())
			return
		}
	}
}

func nodeUpdateFn(vxlanDevice *netlink.Vxlan) func(oldObj, newObj interface{}) {
	return func(oldObj, newObj interface{}) {
		oldNode := oldObj.(*coreV1.Node)
		newNode := newObj.(*coreV1.Node)
		if oldNode.Annotations[mycniVtepMacAnnotationKey] == newNode.Annotations[mycniVtepMacAnnotationKey] {
			return
		}

		klog.Infof("node update event: %s", newNode.Name)
		if err := handlerAddOrUpdate(vxlanDevice, newObj); err != nil {
			klog.Errorf("handlerAddOrUpdate error: %s", err.Error())
			return
		}
	}
}

func nodeDelFn(vxlanDevice *netlink.Vxlan) func(obj interface{}) {
	return func(obj interface{}) {
		// filter函数已对类型做了过滤，这里直接断言ok
		node := obj.(*coreV1.Node)
		_, ipnet, err := net.ParseCIDR(node.Spec.PodCIDR)
		if err != nil {
			klog.Errorf("ParseCIDR %s error", node.Spec.PodCIDR)
			return
		}

		vtepMacStr := node.Annotations[mycniVtepMacAnnotationKey]
		if vtepMacStr == "" {
			klog.Errorf("node %s vtep mac is null", node.Name)
			return
		}
		vtepMac, err := net.ParseMAC(vtepMacStr)
		if err != nil {
			klog.Errorf("ParseMAC %s error", vtepMacStr)
			return
		}

		hostIP := net.ParseIP(node.Annotations[mycniHostIPAnnotationKey])
		if hostIP == nil {
			klog.Errorf("%s: hostIP is nil", node.Name)
			return
		}

		klog.Infof("node delete event: %s", node.Name)
		if err = pkg.DelArp(vxlanDevice.Index, ipnet.IP, vtepMac); err != nil {
			klog.Errorf("node %s add event DelARP error: %s", node.Name, err.Error())
			return
		}
		klog.Infof("DelARP: arp -i %s -d %s", vxlanDevice.Name, ipnet.IP.String())

		if err = pkg.DelFDB(vxlanDevice.Index, hostIP, vtepMac); err != nil {
			klog.Errorf("node %s add event DelFDB error: %s", node.Name, err.Error())
			return
		}
		klog.Infof("DelFDB: bridge fdb del %s dev %s dst %s", vtepMac.String(), vxlanDevice.Name, hostIP)

		if err = pkg.DelRoute(vxlanDevice.Index, ipnet, ipnet.IP); err != nil {
			klog.Errorf("node %s add event DelRoute error: %s", node.Name, err.Error())
			return
		}
		klog.Infof("DelRoute: ip route del %s via %s dev %s", ipnet.String(), ipnet.IP, vxlanDevice.Name)
	}
}
