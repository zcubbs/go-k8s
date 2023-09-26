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
	awxNamespace            = "awx"
	awxOperatorRepoUrl      = "https://ansible.github.io/awx-operator/"
	awxOperatorChartName    = "awx-operator"
	awxOperatorChartVersion = ""

	awxOperatorDeploymentName = "awx-operator"

	awxServiceTypeClusterIP = "ClusterIP"
	awxServiceTypeNodePort  = "NodePort"
)

type Values struct {
	InstanceName string
	ChartVersion string
	AdminUser    string
	AdminPass    string
	ServiceType  string
	IsNodePort   bool
	Namespace    string
}

func Install(values Values, kubeconfig string, debug bool) error {
	if err := validateValues(&values); err != nil {
		return err
	}

	err := helm.Install(helm.Chart{
		Name:            awxOperatorChartName,
		Repo:            awxOperatorChartName,
		URL:             awxOperatorRepoUrl,
		Version:         values.ChartVersion,
		Values:          nil,
		ValuesFiles:     nil,
		Namespace:       awxNamespace,
		Upgrade:         true,
		CreateNamespace: true,
	}, kubeconfig, debug)
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
		Namespace:     values.Namespace,
		IsIpv6:        false,
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
	return helm.Uninstall(helm.Chart{
		Name:      awxOperatorChartName,
		Namespace: awxNamespace,
	}, kubeconfig, debug)
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
	AdminUser     string
	AdminPassword string
	NoLog         bool
}

var instanceTmpl = `
apiVersion: awx.ansible.com/v1beta1
kind: AWX
metadata:
  name: {{ .Name }}
  namespace: {{ .Namespace }}
spec:
  service_type: ClusterIP
  ingress_type: none
  ipv6_disabled: true
  no_log: true
  admin_user: {{ .AdminUser }}

`

var adminPasswordSecretTmpl = `
apiVersion: v1
kind: Secret
metadata:
  name: {{ .Name }}-admin-password
  namespace: {{ .Namespace }}
stringData:
  password: {{ .Password }}

`

func validateValues(values *Values) error {
	if values.ChartVersion == "" {
		values.ChartVersion = awxOperatorChartVersion
	}
	if values.ServiceType == "" {
		values.ServiceType = awxServiceTypeClusterIP
	}
	if values.ServiceType != awxServiceTypeClusterIP && values.ServiceType != awxServiceTypeNodePort {
		return fmt.Errorf("invalid service type %s, must be %s or %s", values.ServiceType, awxServiceTypeClusterIP, awxServiceTypeNodePort)
	}
	if values.ServiceType == awxServiceTypeNodePort {
		values.IsNodePort = true
	}
	if values.InstanceName == "" {
		values.InstanceName = awxInstanceDefaultName
	}
	return nil
}
