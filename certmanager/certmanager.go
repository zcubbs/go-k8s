package certmanager

import (
	"context"
	"fmt"
	"github.com/zcubbs/go-k8s/helm"
	"github.com/zcubbs/go-k8s/kubernetes"
	"github.com/zcubbs/x/pretty"
	"github.com/zcubbs/x/yaml"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"time"
)

const (
	certmanagerDefaultChartVersion  = ""
	certmanagerString               = "cert-manager"
	certmanagerChartName            = certmanagerString
	certmanagerHelmRepoName         = "jetstack"
	certmanagerHelmRepoURL          = "https://charts.jetstack.io"
	certmanagerNamespace            = certmanagerString
	certmanagerDeploymentName       = certmanagerString
	defaultIngressClassResolver     = certmanagerString
	letsencryptStagingIssuerName    = "letsencrypt-staging"
	letsencryptProductionIssuerName = "letsencrypt"
	letsencryptStagingServer        = "https://acme-staging-v02.api.letsencrypt.org/directory"
	letsencryptProductionServer     = "https://acme-v02.api.letsencrypt.org/directory"
)

type Values struct {
	Version                         string
	LetsencryptIssuerEnabled        bool
	LetsencryptIssuerEmail          string
	LetsEncryptIngressClassResolver string
	HttpChallengeEnabled            bool
	DnsChallengeEnabled             bool
	DnsProvider                     string
	DnsRecursiveNameserver          string
	DnsRecursiveServerOnly          bool
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
	configFileContent, err := yaml.ApplyTmpl(valuesFileTmpl, values, debug)
	if err != nil {
		return fmt.Errorf("failed to apply template \n %w", err)
	}

	valuesPath := getTmpFilePath("values")
	// write tmp manifest
	err = os.WriteFile(valuesPath, configFileContent, 0600)
	if err != nil {
		return fmt.Errorf("failed to write traefik values.yaml \n %w", err)
	}

	err = helm.Install(helm.Chart{
		Name:            certmanagerChartName,
		Repo:            certmanagerHelmRepoName,
		URL:             certmanagerHelmRepoURL,
		Version:         values.Version,
		Values:          nil,
		ValuesFiles:     []string{valuesPath},
		Namespace:       certmanagerNamespace,
		Upgrade:         true,
		CreateNamespace: true,
	}, kubeconfig, debug)

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
			IssuerName:           letsencryptStagingIssuerName,
			IssuerEmail:          values.LetsencryptIssuerEmail,
			IssuerServer:         letsencryptStagingServer,
			IngressClassResolver: values.LetsEncryptIngressClassResolver,
			Namespace:            certmanagerNamespace,
		}, kubeconfig, debug)
		if err != nil {
			return fmt.Errorf("failed to apply letsencrypt staging issuer \n %w", err)
		}

		// production
		err = applyIssuer(Issuer{
			IssuerName:           letsencryptProductionIssuerName,
			IssuerEmail:          values.LetsencryptIssuerEmail,
			IssuerServer:         letsencryptProductionServer,
			IngressClassResolver: values.LetsEncryptIngressClassResolver,
			Namespace:            certmanagerNamespace,
		}, kubeconfig, debug)
		if err != nil {
			return fmt.Errorf("failed to apply letsencrypt production issuer \n %w", err)
		}
	}

	return nil
}

func Uninstall(kubeconfig string, debug bool) error {
	return helm.Uninstall(helm.Chart{
		Name:      certmanagerChartName,
		Namespace: certmanagerNamespace,
	}, kubeconfig, debug)
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
			values.LetsEncryptIngressClassResolver = defaultIngressClassResolver
		}
	}

	return nil
}

func getTmpFilePath(name string) string {
	return os.TempDir() + "/" + name + "-" + time.Now().Format("20060102150405") + ".yaml"
}

func applyIssuer(issuer Issuer, kubeconfig string, debug bool) error {
	return kubernetes.ApplyManifest(
		issuerTmpl,
		issuer,
		debug,
	)
}

type Issuer struct {
	IssuerName           string
	IssuerEmail          string
	IssuerServer         string
	IngressClassResolver string
	Namespace            string
	DnsChallengeEnabled  bool
	HttpChallengeEnabled bool
}

type ValuesFile struct {
	InstallCRDs             bool
	ReplicaCount            int
	DnsEnabled              bool
	DnsProvider             string
	DnsRecursiveNameservers string
	DnsRecursiveServerOnly  bool
}

const valuesFileTmpl = `---
installCRDs: true
replicaCount: 1
extraArgs:
  {{- if .DnsEnabled }}
  - --dns01-recursive-nameservers={{ .DnsRecursiveNameserversMerged }}
  {{- end }}
  {{- if .DnsRecursiveServerOnly }}
  - --dns01-recursive-server-only
  {{- end }}
podDnsPolicy: None
podDnsConfig:
  nameservers:
    {{- range $i, $arg := .DnsRecursiveNameservers }}
    - "{{ printf "%s" . }}"
    {{- end }}
`

const dnsAzureClientSecretTmpl = `---
apiVersion: v1
kind: Secret
metadata:
  name: azuredns-config
  namespace: {{ .Namespace }}
type: Opaque
data:
  client-secret: {{ .ClientSecret }}
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
          {{- if .DnsProvider }}:
            {{- if eq .DnsProvider "azure" }}
            azureDNS:
              clientID: {{ .DnsAzureClientID }}
              clientSecretSecretRef:
                name: azuredns-config
              environment: AzurePublicCloud
              hostedZoneName: {{ .DnsAzureHostedZoneName }}
              resourceGroupName: {{ .DnsAzureResourceGroupName }}
              subscriptionID: {{ .DnsAzureSubscriptionID }}
              tenantID: {{ .DnsAzureTenantID }}

      {{- else if .HttpChallengeEnabled }}
      - http01:
          ingress:
            class: {{ .IngressClassResolver }}
      {{- end }}
`
