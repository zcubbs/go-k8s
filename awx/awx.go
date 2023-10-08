package awx

import (
	"context"
	"fmt"
	"github.com/zcubbs/go-k8s/helm"
	"github.com/zcubbs/go-k8s/kubernetes"
	"time"
)

const (
	awxInstanceDefaultName  = "awx"
	awxNamespace            = "default"
	awxOperatorRepoUrl      = "https://ansible.github.io/awx-operator/"
	awxOperatorChartName    = "awx-operator"
	awxOperatorChartVersion = ""

	awxOperatorDeploymentName = "awx-operator-controller-manager"
)

type Values struct {
	InstanceName string
	ChartVersion string
	AdminUser    string
	AdminPass    string
	IsNodePort   bool
	NodePort     int
}

func Install(values Values, kubeconfig string, debug bool) error {
	if err := validateValues(&values); err != nil {
		return err
	}

	helmClient := helm.NewClient()
	helmClient.Settings.KubeConfig = kubeconfig
	helmClient.Settings.SetNamespace(awxNamespace)
	helmClient.Settings.Debug = debug

	// add awx-operator helm repo
	err := helmClient.RepoAddAndUpdate(awxOperatorChartName, awxOperatorRepoUrl)
	if err != nil {
		return fmt.Errorf("failed to add helm repo: %w", err)
	}

	// install awx-operator
	err = helmClient.InstallChart(helm.Chart{
		ChartName:       awxOperatorChartName,
		ReleaseName:     awxOperatorChartName,
		RepoName:        awxOperatorChartName,
		Values:          nil,
		ValuesFiles:     nil,
		Debug:           debug,
		CreateNamespace: true,
		Upgrade:         true,
	})
	if err != nil {
		return fmt.Errorf("failed to install awx-operator \n %w", err)
	}

	// wait for awx-operator to be ready
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	err = kubernetes.IsDeploymentReady(
		ctxWithTimeout,
		kubeconfig,
		awxNamespace,
		[]string{
			awxOperatorDeploymentName,
		},
		debug,
	)
	if err != nil {
		return fmt.Errorf("failed to wait for awx-operator to be ready \n %w", err)
	}

	// apply awx instance
	err = addInstance(instanceTmplValues{
		Name:          values.InstanceName,
		Namespace:     awxNamespace,
		IsIpv6:        false,
		IsNodePort:    values.IsNodePort,
		NodePort:      values.NodePort,
		AdminUser:     values.AdminUser,
		AdminPassword: values.AdminPass,
		NoLog:         true,
	}, kubeconfig, debug)
	if err != nil {
		return fmt.Errorf("failed to apply awx instance \n %w", err)
	}

	return nil
}

func Uninstall(kubeconfig string, debug bool) error {
	helmClient := helm.NewClient()
	helmClient.Settings.KubeConfig = kubeconfig
	helmClient.Settings.SetNamespace(awxNamespace)
	helmClient.Settings.Debug = debug

	// uninstall awx-operator
	return helmClient.UninstallChart(awxOperatorChartName)
}

func addInstance(values instanceTmplValues, _ string, debug bool) error {
	err := kubernetes.ApplyManifest(adminPasswordSecretTmpl, values, debug)
	if err != nil {
		return fmt.Errorf("failed to apply awx admin password secret \n %w", err)
	}

	err = kubernetes.ApplyManifest(instanceTmpl, values, debug)
	if err != nil {
		return fmt.Errorf("failed to apply awx instance \n %w", err)
	}
	return nil
}

type instanceTmplValues struct {
	Name          string
	Namespace     string
	IsIpv6        bool
	IsNodePort    bool
	NodePort      int
	AdminUser     string
	AdminPassword string
	NoLog         bool
}

// #nosec G101
var instanceTmpl = `
apiVersion: awx.ansible.com/v1beta1
kind: AWX
metadata:
  name: {{ .Name }}
  namespace: {{ .Namespace }}
spec:
  {{- if .IsIpv6 }}
  ipv6_enabled: true
  {{- end }}
  {{- if .IsNodePort }}
  service_type: NodePort
  nodeport_port: {{ .NodePort }}
  {{- else }}
  service_type: ClusterIP
  {{- end }}
  ingress_type: none
  no_log: {{ .NoLog }}
  admin_user: {{ .AdminUser }}

`

// #nosec G101
var adminPasswordSecretTmpl = `
apiVersion: v1
kind: Secret
metadata:
  name: {{ .Name }}-admin-password
  namespace: {{ .Namespace }}
stringData:
  password: {{ .AdminPassword }}

`

func validateValues(values *Values) error {
	if values.ChartVersion == "" {
		values.ChartVersion = awxOperatorChartVersion
	}
	if values.AdminUser == "" {
		values.AdminUser = "admin"
	}
	if values.IsNodePort && values.NodePort == 0 {
		values.NodePort = 30080
	}
	if values.InstanceName == "" {
		values.InstanceName = awxInstanceDefaultName
	}
	return nil
}
