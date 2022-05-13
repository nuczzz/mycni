package main

import (
	"encoding/json"
	"strings"

	"github.com/pkg/errors"
)

type IPAM struct {
	Type       string `json:"type"`
	Subnet     string `json:"subnet"`
	RangeStart string `json:"rangeStart"`
	RangeEnd   string `json:"rangeEnd"`
}

type MyCNIConfig struct {
	CNIVersion string `json:"cniVersion"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	IPAM       IPAM   `json:"ipam"`
}

func loadConfig(bytes []byte) (*MyCNIConfig, error) {
	var conf MyCNIConfig
	if err := json.Unmarshal(bytes, &conf); err != nil {
		return nil, errors.Wrap(err, "json  Unmarshal error")
	}

	return &conf, nil
}

type cniArgs struct {
	namespace   string
	podName     string
	containerID string
}

func parseArgs(args string) *cniArgs {
	m := make(map[string]string)

	attrs := strings.Split(args, ";")

	for _, attr := range attrs {
		kv := strings.Split(attr, "=")
		if len(kv) != 2 {
			continue
		}

		m[kv[0]] = kv[1]
	}

	return &cniArgs{
		namespace:   m["K8S_POD_NAMESPACE"],
		podName:     m["K8S_POD_NAME"],
		containerID: m["K8S_POD_INFRA_CONTAINER_ID"],
	}
}