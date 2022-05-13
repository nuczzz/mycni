package pkg

import (
	"context"
	"encoding/json"
	"os"

	"github.com/pkg/errors"
	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listersCoreV1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	clientSet *kubernetes.Clientset
	factory   informers.SharedInformerFactory
)

func InitK8sClient(stopCh <-chan struct{}) error {
	// in-cluster
	cfg, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		return errors.Wrap(err, "BuildConfigFromFlags error")
	}

	clientSet, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return errors.Wrap(err, "NewForConfig error")
	}

	factory = informers.NewSharedInformerFactory(clientSet, 0)

	return initNodeInformer(stopCh)
}

var (
	nodeInformer cache.SharedIndexInformer
	nodeLister   listersCoreV1.NodeLister
)

func initNodeInformer(stopCh <-chan struct{}) error {
	nodeInformer = factory.Core().V1().Nodes().Informer()
	go nodeInformer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, nodeInformer.HasSynced) {
		return errors.Errorf("WaitForCacheSync expect true but got false")
	}

	nodeLister = factory.Core().V1().Nodes().Lister()
	return nil
}

func GetCurrentNodeName() (string, error) {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		podName := os.Getenv("POD_NAME")
		podNamespace := os.Getenv("POD_NAMESPACE")
		if podName == "" || podNamespace == "" {
			return "", errors.Errorf("env POD_NAME and POD_NAMESPACE must be set")
		}

		pod, err := clientSet.CoreV1().Pods(podNamespace).Get(context.TODO(), podName, metaV1.GetOptions{})
		if err != nil {
			return "", errors.Wrapf(err, "get pod %s/%s error", podNamespace, podName)
		}

		nodeName = pod.Spec.NodeName
		if podName == "" {
			return "", errors.Errorf("node name not present in pod spec %s/%s", podNamespace, podName)
		}
	}

	return nodeName, nil
}

func GetCurrentNode() (*coreV1.Node, error) {
	nodeName, err := GetCurrentNodeName()
	if err != nil {
		return nil, errors.Wrap(err, "GetCurrentNodeName error")
	}

	node, err := nodeLister.Get(nodeName)
	if err != nil {
		return nil, errors.Wrapf(err, "get node %s error", nodeName)
	}

	return node, nil
}

func InitController(
	filter func(interface{}) bool,
	addFn, delFn func(interface{}),
	updateFn func(interface{}, interface{}),
) {
	nodeInformer.AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: filter,
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    addFn,
			UpdateFunc: updateFn,
			DeleteFunc: delFn,
		},
	})
}

func PatchNode(oldNode, newNode *coreV1.Node) error {
	oldData, err := json.Marshal(oldNode)
	if err != nil {
		return errors.Wrap(err, "Marshal old node error")
	}

	newData, err := json.Marshal(newNode)
	if err != nil {
		return errors.Wrap(err, "Marshal new node error")
	}

	patchBytes, err := strategicpatch.CreateTwoWayMergePatch(oldData, newData, coreV1.Node{})
	if err != nil {
		return errors.Wrap(err, "CreateTwoWayMergePatch error")
	}

	if _, err = clientSet.CoreV1().Nodes().Patch(context.TODO(), oldNode.Name, types.StrategicMergePatchType,
		patchBytes, metaV1.PatchOptions{}); err != nil {
		return errors.Wrapf(err, "patch node %s error", oldNode.Name)
	}

	return nil
}
