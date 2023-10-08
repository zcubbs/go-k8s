package rancher

import (
	"fmt"
	"github.com/zcubbs/go-k8s/helm"
	"github.com/zcubbs/x/yaml"
	"os"
)

const (
	defaultVersion    = ""
	helmRepoURL       = "https://releases.rancher.com/server-charts/stable"
	helmRepoName      = "rancher-stable"
	defaultNamespace  = "cattle-system"
	defaultChartName  = "rancher"
	defaultValuesFile = "values.yaml"
)

type Values struct {
	Version  string
	Hostname string
}

func Install(values *Values, kubeconfig string, debug bool) error {
	err := validateValues(values)
	if err != nil {
		return err
	}

	// create values file
	valuesFileData, err := yaml.ApplyTmpl(
		valuesTmpl,
		values,
		debug,
	)
	if err != nil {
		return fmt.Errorf("failed to parse values template file: %w", err)
	}

	valuesFilePath := fmt.Sprintf("%s/%s", os.TempDir(), defaultValuesFile)
	// write values file
	err = os.WriteFile(valuesFilePath, valuesFileData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write values file: %w", err)
	}

	helmClient := helm.NewClient()
	helmClient.Settings.KubeConfig = kubeconfig
	helmClient.Settings.SetNamespace(defaultNamespace)
	helmClient.Settings.Debug = debug

	err = helmClient.RepoAdd(helmRepoName, helmRepoURL)
	if err != nil {
		return fmt.Errorf("failed to add helm repo: %w", err)
	}

	err = helmClient.RepoUpdate()
	if err != nil {
		return fmt.Errorf("failed to update helm repo: %w", err)
	}

	err = helmClient.InstallChart(defaultChartName, helmRepoName, defaultChartName, nil)
	if err != nil {
		return fmt.Errorf("failed to install helm chart: %w", err)
	}

	return nil
}

func validateValues(values *Values) error {
	if values.Version == "" {
		values.Version = defaultVersion
	}
	if values.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}

	return nil
}

const valuesTmpl = `
---
# Default values for rancher.
# This is a YAML-formatted file.
# Declare variables to be passed into your templates.
replicas: 1
hostname: {{ .Hostname }}
ingress:
  enabled: false
  tls:
    source: external
`
