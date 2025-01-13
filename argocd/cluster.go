package argocd

import (
	"fmt"

	"github.com/zcubbs/go-k8s/kubernetes"
)

type Cluster struct {
	Name      string `mapstructure:"name" json:"name" yaml:"name"`
	Namespace string `mapstructure:"namespace" json:"namespace" yaml:"namespace"`
	ServerUrl string `mapstructure:"serverUrl" json:"serverUrl" yaml:"serverUrl"`
	Config    string `mapstructure:"config" json:"config" yaml:"config"`
}

func CreateCluster(cluster Cluster, _ string, debug bool) error {
	cluster.Namespace = argocdNamespace
	// Apply template
	err := kubernetes.ApplyManifest(clusterTmpl, cluster, debug)
	if err != nil {
		return fmt.Errorf("failed to create cluster: %w", err)
	}
	return nil
}

var clusterTmpl = `---

apiVersion: v1
kind: Secret
metadata:
  name: {{ .Name }}
  namespace: {{ .Namespace }}
  labels:
    argocd.argoproj.io/secret-type: cluster
data:
  config: {{ .Config }}
  name: {{ .Name }}
  server: {{ .ServerUrl }}
type: Opaque

`
