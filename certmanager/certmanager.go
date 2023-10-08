package certmanager

import (
	"context"
	"fmt"
	"github.com/zcubbs/go-k8s/helm"
	"github.com/zcubbs/go-k8s/kubernetes"
	"github.com/zcubbs/x/pretty"
	"github.com/zcubbs/x/secret"
	"github.com/zcubbs/x/yaml"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"strings"
	"time"
)

const (
	certmanagerDefaultChartVersion = ""
	certmanagerString              = "cert-manager"
	certmanagerChartName           = certmanagerString
	certmanagerHelmRepoName        = "jetstack"
	certmanagerHelmRepoURL         = "https://charts.jetstack.io"
	certmanagerNamespace           = certmanagerString
	certmanagerDeploymentName      = certmanagerString

	letsencryptStagingIssuerName    = "letsencrypt-staging"
	letsencryptProductionIssuerName = "letsencrypt"
	letsencryptStagingServer        = "https://acme-staging-v02.api.letsencrypt.org/directory"
	letsencryptProductionServer     = "https://acme-v02.api.letsencrypt.org/directory"
	kubeSystemNamespace             = "kube-system"
)

type Values struct {
	Version                         string
	LetsencryptIssuerEnabled        bool
	LetsencryptIssuerEmail          string
	LetsEncryptIngressClassResolver string
	HttpChallengeEnabled            bool
	DnsChallengeEnabled             bool
	DnsProvider                     string
	DnsRecursiveNameservers         []string
	DnsRecursiveNameserversOnly     bool
	DnsAzureClientID                string
	DnsAzureClientSecret            string
	DnsAzureHostedZoneName          string
	DnsAzureResourceGroupName       string
	DnsAzureSubscriptionID          string
	DnsAzureTenantID                string
}

func Install(values Values, kubeconfig string, debug bool) error {
	if debug {
		pretty.PrintJson(values)
	}

	if err := validateValues(&values); err != nil {
		return err
	}

	// create cert-manager values.yaml from template
	configFileContent, err := yaml.ApplyTmpl(
		valuesFileTmpl,
		ValuesFile{
			InstallCRDs:                   true,
			ReplicaCount:                  1,
			DnsEnabled:                    values.DnsChallengeEnabled,
			DnsRecursiveNameservers:       removePortFromHosts(values.DnsRecursiveNameservers),
			DnsRecursiveNameserversMerged: getMergedRecursiveNameservers(values.DnsRecursiveNameservers),
			DnsRecursiveNameserversOnly:   values.DnsRecursiveNameserversOnly,
		},
		debug,
	)
	if err != nil {
		return fmt.Errorf("failed to apply template \n %w", err)
	}

	valuesPath := getTmpFilePath("values")
	// write tmp manifest
	err = os.WriteFile(valuesPath, configFileContent, 0600)
	if err != nil {
		return fmt.Errorf("failed to write traefik values.yaml \n %w", err)
	}

	helmClient := helm.NewClient()
	helmClient.Settings.KubeConfig = kubeconfig
	helmClient.Settings.Debug = debug
	helmClient.Settings.SetNamespace(certmanagerNamespace)

	// add repo
	err = helmClient.RepoAddAndUpdate(certmanagerHelmRepoName, certmanagerHelmRepoURL)
	if err != nil {
		return fmt.Errorf("failed to add cert-manager helm repo \n %w", err)
	}

	err = helmClient.InstallChart(helm.Chart{
		ChartName:       certmanagerChartName,
		ReleaseName:     certmanagerChartName,
		RepoName:        certmanagerHelmRepoName,
		Values:          nil,
		ValuesFiles:     []string{valuesPath},
		Debug:           debug,
		CreateNamespace: true,
		Upgrade:         true,
	})
	if err != nil {
		return fmt.Errorf("failed to install cert-manager \n %w", err)
	}

	// check if deploy is ready
	// wait for cert-manager to be ready
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	err = kubernetes.IsDeploymentReady(
		ctxWithTimeout,
		kubeconfig,
		certmanagerNamespace,
		[]string{
			certmanagerDeploymentName,
		},
		debug,
	)
	if err != nil {
		return fmt.Errorf("failed to wait for cert-manager to be ready \n %w", err)
	}

	// parse secret values
	if err := parseSecretValues(&values); err != nil {
		return err
	}

	// apply letsencrypt issuers
	if values.LetsencryptIssuerEnabled {
		if values.DnsChallengeEnabled {
			// create secret
			if values.DnsProvider == "azure" {
				err = kubernetes.CreateGenericSecret(
					context.Background(),
					kubeconfig,
					v1.Secret{
						ObjectMeta: metav1.ObjectMeta{
							Name: "azuredns-config",
						},
						Type: v1.SecretTypeOpaque,
						Data: map[string][]byte{
							"client-secret": []byte(values.DnsAzureClientSecret),
						},
					},
					[]string{certmanagerNamespace},
					true,
					debug,
				)
				if err != nil {
					return fmt.Errorf("failed to create azuredns-config secret \n %w", err)
				}
			} else {
				return fmt.Errorf("dns provider %s is not supported", values.DnsProvider)
			}
		}

		// staging
		err = applyIssuer(Issuer{
			IssuerName:                letsencryptStagingIssuerName,
			IssuerEmail:               values.LetsencryptIssuerEmail,
			IssuerServer:              letsencryptStagingServer,
			IngressClassResolver:      values.LetsEncryptIngressClassResolver,
			Namespace:                 kubeSystemNamespace,
			HttpChallengeEnabled:      values.HttpChallengeEnabled,
			DnsChallengeEnabled:       values.DnsChallengeEnabled,
			DnsProvider:               values.DnsProvider,
			DnsAzureClientID:          values.DnsAzureClientID,
			DnsAzureClientSecret:      values.DnsAzureClientSecret,
			DnsAzureHostedZoneName:    values.DnsAzureHostedZoneName,
			DnsAzureResourceGroupName: values.DnsAzureResourceGroupName,
			DnsAzureSubscriptionID:    values.DnsAzureSubscriptionID,
			DnsAzureTenantID:          values.DnsAzureTenantID,
		}, kubeconfig, debug)
		if err != nil {
			return fmt.Errorf("failed to apply letsencrypt staging issuer \n %w", err)
		}

		// production
		err = applyIssuer(Issuer{
			IssuerName:                letsencryptProductionIssuerName,
			IssuerEmail:               values.LetsencryptIssuerEmail,
			IssuerServer:              letsencryptProductionServer,
			IngressClassResolver:      values.LetsEncryptIngressClassResolver,
			Namespace:                 kubeSystemNamespace,
			HttpChallengeEnabled:      values.HttpChallengeEnabled,
			DnsChallengeEnabled:       values.DnsChallengeEnabled,
			DnsProvider:               values.DnsProvider,
			DnsAzureClientID:          values.DnsAzureClientID,
			DnsAzureClientSecret:      values.DnsAzureClientSecret,
			DnsAzureHostedZoneName:    values.DnsAzureHostedZoneName,
			DnsAzureResourceGroupName: values.DnsAzureResourceGroupName,
			DnsAzureSubscriptionID:    values.DnsAzureSubscriptionID,
			DnsAzureTenantID:          values.DnsAzureTenantID,
		}, kubeconfig, debug)
		if err != nil {
			return fmt.Errorf("failed to apply letsencrypt production issuer \n %w", err)
		}
	}

	return nil
}

func Uninstall(kubeconfig string, debug bool) error {
	helmClient := helm.NewClient()
	helmClient.Settings.KubeConfig = kubeconfig
	helmClient.Settings.Debug = debug

	return helmClient.UninstallChart(certmanagerChartName)
}

func validateValues(values *Values) error {
	if values.Version == "" {
		values.Version = certmanagerDefaultChartVersion
	}

	if values.LetsencryptIssuerEnabled {
		if values.LetsencryptIssuerEmail == "" {
			return fmt.Errorf("letsencrypt issuer email is required")
		}

		if values.LetsEncryptIngressClassResolver == "" {
			return fmt.Errorf("letsencrypt ingress class resolver is required")
		}
	}

	return nil
}

func getTmpFilePath(name string) string {
	return os.TempDir() + "/" + name + "-" + time.Now().Format("20060102150405") + ".yaml"
}

func parseSecretValues(values *Values) error {
	if values.DnsChallengeEnabled {
		if values.DnsProvider == "azure" {
			// load env vars
			azureClientId, err := secret.Provide(values.DnsAzureClientID)
			if err != nil {
				return fmt.Errorf("failed to provide azure client id \n %w", err)
			}
			azureClientSecret, err := secret.Provide(values.DnsAzureClientSecret)
			if err != nil {
				return fmt.Errorf("failed to provide azure client secret \n %w", err)
			}
			azureResourceGroup, err := secret.Provide(values.DnsAzureResourceGroupName)
			if err != nil {
				return fmt.Errorf("failed to provide azure resource group \n %w", err)
			}
			azureSubscriptionID, err := secret.Provide(values.DnsAzureSubscriptionID)
			if err != nil {
				return fmt.Errorf("failed to provide azure subscription id \n %w", err)
			}
			azureTenantID, err := secret.Provide(values.DnsAzureTenantID)
			if err != nil {
				return fmt.Errorf("failed to provide azure tenant id \n %w", err)
			}

			// validate env vars
			if azureClientId == "" {
				return fmt.Errorf("azure client id is required")
			}

			if azureClientSecret == "" {
				return fmt.Errorf("azure client secret is required")
			}

			if azureResourceGroup == "" {
				return fmt.Errorf("azure resource group is required")
			}

			if azureSubscriptionID == "" {
				return fmt.Errorf("azure subscription id is required")
			}

			if azureTenantID == "" {
				return fmt.Errorf("azure tenant id is required")
			}

			values.DnsAzureClientID = azureClientId
			values.DnsAzureClientSecret = azureClientSecret
			values.DnsAzureResourceGroupName = azureResourceGroup
			values.DnsAzureSubscriptionID = azureSubscriptionID
			values.DnsAzureTenantID = azureTenantID
		} else {
			return fmt.Errorf("dns provider %s is not supported", values.DnsProvider)
		}
	}

	return nil
}

func applyIssuer(issuer Issuer, _ string, debug bool) error {
	return kubernetes.ApplyManifest(
		issuerTmpl,
		issuer,
		debug,
	)
}

func removePortFromHosts(hosts []string) []string {
	var newHosts []string
	for _, host := range hosts {
		newHosts = append(newHosts, removePortFromHost(host))
	}
	return newHosts
}

func removePortFromHost(host string) string {
	parts := strings.Split(host, ":")
	if len(parts) > 1 {
		return parts[0]
	}

	return host
}

func getMergedRecursiveNameservers(nameservers []string) string {
	var merged string
	for i, ns := range nameservers {
		if i == 0 {
			merged = ns
		} else {
			merged = merged + "," + ns
		}
	}
	return merged
}

type Issuer struct {
	IssuerName                string
	IssuerEmail               string
	IssuerServer              string
	IngressClassResolver      string
	Namespace                 string
	HttpChallengeEnabled      bool
	DnsChallengeEnabled       bool
	DnsProvider               string
	DnsAzureClientID          string
	DnsAzureClientSecret      string
	DnsAzureHostedZoneName    string
	DnsAzureResourceGroupName string
	DnsAzureSubscriptionID    string
	DnsAzureTenantID          string
}

type ValuesFile struct {
	InstallCRDs                   bool
	ReplicaCount                  int
	DnsEnabled                    bool
	DnsRecursiveNameserversMerged string
	DnsRecursiveNameservers       []string
	DnsRecursiveNameserversOnly   bool
	PrometheusEnabled             bool
}

const valuesFileTmpl = `---
installCRDs: true
replicaCount: 1
prometheus:
  enabled: {{ .PrometheusEnabled }}
{{- if and .DnsEnabled .DnsRecursiveNameservers .DnsRecursiveNameserversOnly .DnsRecursiveNameserversMerged }}
extraArgs:
  {{- if and .DnsRecursiveNameserversMerged }}
  - --dns01-recursive-nameservers={{ .DnsRecursiveNameserversMerged }}
  {{- end }}
  {{- if and .DnsRecursiveNameserversOnly }}
  - --dns01-recursive-nameservers-only
  {{- end }}
podDnsPolicy: None
podDnsConfig:
  nameservers:
    {{- range $i, $arg := .DnsRecursiveNameservers }}
    - "{{ printf "%s" . }}"
    {{- end }}
{{- end }}
`

const issuerTmpl = `---

apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: {{ .IssuerName }}
  namespace: {{ .Namespace }}
spec:
  acme:
    email: {{ .IssuerEmail }}
    server: {{ .IssuerServer }}
    privateKeySecretRef:
      name: {{ .IssuerName }}
    solvers:
      {{- if .DnsChallengeEnabled }}
      - dns01:
          {{- if eq .DnsProvider "azure" }}
          azureDNS:
            clientID: {{ .DnsAzureClientID }}
            clientSecretSecretRef:
              key: client-secret
              name: azuredns-config
            environment: AzurePublicCloud
            hostedZoneName: {{ .DnsAzureHostedZoneName }}
            resourceGroupName: {{ .DnsAzureResourceGroupName }}
            subscriptionID: {{ .DnsAzureSubscriptionID }}
            tenantID: {{ .DnsAzureTenantID }}
        selector:
          dnsZones:
		    - {{ .DnsAzureHostedZoneName }}
          {{- end }}
      {{- else if .HttpChallengeEnabled }}
      - http01:
          ingress:
            class: {{ .IngressClassResolver }}
      {{- end }}
`
