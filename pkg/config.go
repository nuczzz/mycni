package pkg

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
)

func InitCNIPluginConfigFile(podCidr string) error {
	fd, err := os.OpenFile("/etc/cni/net.d/00-mycni.conflist",
		os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.ModeAppend|os.ModePerm)
	if err != nil {
		return errors.Wrap(err, "open cni config file error")
	}
	defer fd.Close()

	if _, err = fd.Write([]byte(fmt.Sprintf(cniConfTemplate, podCidr))); err != nil {
		return errors.Wrap(err, "write cni config file error")
	}

	return nil
}

var cniConfTemplate = `{
  "name": "mycni0",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "mycni",
      "ipam": {
        "type": "host-local",
        "subnet": "%s"
      }
    }
  ]
}`
