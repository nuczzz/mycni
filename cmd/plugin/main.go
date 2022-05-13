package main

import (
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"

	"mycni/cmd/plugin/log"
)

const (
	defaultLogFile  = "/var/log/mycni.log"
)

func main() {
	log.InitZapLog(defaultLogFile)

	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("mycni"))
}

func cmdCheck(*skel.CmdArgs) error {
	return nil
}