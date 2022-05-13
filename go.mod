module mycni

go 1.13

require (
	github.com/containernetworking/cni v1.1.0
	github.com/containernetworking/plugins v1.1.1
	github.com/pkg/errors v0.9.1
	github.com/sanity-io/litter v1.5.5
	github.com/vishvananda/netlink v1.1.1-0.20210330154013-f5de75959ad5
	go.uber.org/zap v1.10.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	k8s.io/api v0.20.7
	k8s.io/apimachinery v0.20.7
	k8s.io/client-go v0.20.7
	k8s.io/component-base v0.20.7
	k8s.io/klog/v2 v2.60.1
	k8s.io/sample-controller v0.20.7
)
