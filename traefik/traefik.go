package traefik

import (
	"context"
	"fmt"
	"github.com/zcubbs/go-k8s/helm"
	"github.com/zcubbs/go-k8s/kubernetes"
	"github.com/zcubbs/x/secret"
	"github.com/zcubbs/x/yaml"
	"os"
	"time"
)

const (
	traefikHelmRepoName = "traefik"
	traefikHelmRepoUrl  = "https://helm.traefik.io/traefik"
	traefikChartName    = "traefik"
	traefikChartVersion = "" // latest
	traefikNamespace    = "traefik"

	traefikDnsResolver = "letsencrypt"

	traefikEndpointWeb       = "80"
	traefikEndpointWebsecure = "443"

	traefikDnsTZ = "Europe/Paris"
)

func Install(values Values, kubeconfig string, debug bool) error {
	if err := validateValues(&values); err != nil {
		return err
	}

	if values.DnsChallengeEnabled {
		if err := configureDNSChallengeVars(values, kubeconfig, debug); err != nil {
			return err
		}
	}

	valuesPath := getTmpFilePath("values")

	// create traefik values.yaml from template
	configFileContent, err := yaml.ApplyTmpl(traefikValuesTmpl, values, debug)
	if err != nil {
		return fmt.Errorf("failed to apply template \n %w", err)
	}

	// write tmp manifest
	err = os.WriteFile(valuesPath, configFileContent, 0600)
	if err != nil {
		return fmt.Errorf("failed to write traefik values.yaml \n %w", err)
	}

	err = helm.Install(helm.Chart{
		Name:            traefikChartName,
		Repo:            traefikHelmRepoName,
		URL:             traefikHelmRepoUrl,
		Version:         traefikChartVersion,
		Values:          nil,
		ValuesFiles:     []string{valuesPath},
		Namespace:       traefikNamespace,
		Upgrade:         true,
		CreateNamespace: true,
	}, kubeconfig, debug)
	if err != nil {
		return err
	}

	// wait for traefik deployment to be ready
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	err = kubernetes.IsDeploymentReady(
		ctxWithTimeout,
		kubeconfig,
		traefikNamespace,
		[]string{"traefik"},
		debug,
	)
	if err != nil {
		return fmt.Errorf("failed to wait for traefik deployment to be ready \n %w", err)
	}

	// prepare default certificate secret
	if values.DefaultCertificateEnabled {
		err := createDefaultCertificateSecret(&values, kubeconfig, debug)
		if err != nil {
			return fmt.Errorf("failed to create default certificate secret \n %w", err)
		}

		// restart traefik
		err = kubernetes.RestartPods(kubeconfig, traefikNamespace, []string{"traefik"}, debug)
		if err != nil {
			return fmt.Errorf("failed to restart traefik \n %w", err)
		}
	}
	return nil
}

func Uninstall(kubeconfig string, debug bool) error {
	return helm.Uninstall(helm.Chart{
		Name:      traefikChartName,
		Namespace: traefikNamespace,
	}, kubeconfig, debug)
}

func createDefaultCertificateSecret(values *Values, kubeconfig string, debug bool) error {
	// create namespace
	err := kubernetes.CreateNamespace(
		kubeconfig,
		[]string{traefikNamespace},
	)
	if err != nil {
		return fmt.Errorf("failed to create namespace %s \n %w", traefikNamespace, err)
	}

	cert, err := secret.Provide(values.DefaultCertificateCert)
	if err != nil {
		return fmt.Errorf("failed to provide default certificate crt \n %w", err)
	}

	key, err := secret.Provide(values.DefaultCertificateKey)
	if err != nil {
		return fmt.Errorf("failed to provide default certificate key \n %w", err)
	}

	values.DefaultCertificateCert = cert
	values.DefaultCertificateKey = key

	// apply template
	if err := applyDefaultCertificateSecret(*values, kubeconfig, debug); err != nil {
		return err
	}

	return nil
}

func applyDefaultCertificateSecret(values Values, _ string, debug bool) error {
	err := kubernetes.ApplyManifest(
		defaultTlsStoreTmpl,
		struct {
			Namespace string
		}{
			Namespace: traefikNamespace,
		},
		debug,
	)
	if err != nil {
		return fmt.Errorf("failed to apply default tls store \n %w", err)
	}

	// Add Default Certificate Secret
	if values.DefaultCertificateEnabled {
		err = kubernetes.ApplyManifest(
			defaultCertificateSecretTmpl,
			DefaultCertificateValues{
				Enabled: values.DefaultCertificateEnabled,
				Base64EncodedCertificate: struct {
					Crt string
					Key string
				}{
					Crt: values.DefaultCertificateCert,
					Key: values.DefaultCertificateKey,
				},
				Namespace: traefikNamespace,
			}, debug)
		if err != nil {
			return fmt.Errorf("failed to apply default certificate secret \n %w", err)
		}
	}

	return nil
}

func getTmpFilePath(name string) string {
	return os.TempDir() + "/" + name + "-" + time.Now().Format("20060102150405") + ".yaml"
}

func validateValues(values *Values) error {
	if values.IngressProvider != "" && values.DnsChallengeEnabled {
		return fmt.Errorf("can't set both ingressProvider and dnsProvider")
	}

	if values.DnsChallengeEnabled {
		if values.DnsResolver == "" {
			values.DnsResolver = traefikDnsResolver
		}
	}

	if values.EndpointsWeb == "" {
		values.EndpointsWeb = traefikEndpointWeb
	}

	if values.EndpointsWebsecure == "" {
		values.EndpointsWebsecure = traefikEndpointWebsecure
	}

	if values.DnsTZ == "" {
		values.DnsTZ = traefikDnsTZ
	}

	if values.DefaultCertificateEnabled {
		if values.DefaultCertificateCert == "" {
			return fmt.Errorf("defaultCertificate.base64EncodedCertificate.crt is required")
		}
		if values.DefaultCertificateKey == "" {
			return fmt.Errorf("defaultCertificate.base64EncodedCertificate.key is required")
		}
	}

	return nil
}

type Values struct {
	AdditionalArguments                []string
	IngressProvider                    string
	DnsChallengeEnabled                bool
	DnsProvider                        string
	DnsResolver                        string
	DnsResolverIPs                     string
	DnsResolverEmail                   string
	EnableDashboard                    bool
	EnableAccessLog                    bool
	DebugLog                           bool
	EndpointsWeb                       string
	EndpointsWebsecure                 string
	ServersTransportInsecureSkipVerify bool
	ForwardedHeaders                   bool
	ForwardedHeadersInsecure           bool
	ForwardedHeadersTrustedIPs         string
	ProxyProtocol                      bool
	ProxyProtocolInsecure              bool
	ProxyProtocolTrustedIPs            string
	DnsTZ                              string

	DefaultCertificateEnabled bool
	DefaultCertificateCert    string
	DefaultCertificateKey     string
}

var traefikValuesTmpl = `
globalArguments:
  - "--global.checknewversion=false"
  - "--global.sendanonymoususage=false"
global:
  sendAnonymousUsage: false
  checkNewVersion: false
  log:
  {{- if .DebugLog }}
    level: DEBUG
  {{- else }}
    level: INFO
  {{- end }}
  accessLogs:
  {{- if .EnableAccessLog }}
    enabled: true
  {{- else }}
    enabled: false
  {{- end }}
service:
  enabled: true
  type: LoadBalancer
rbac:
  enabled: true
additionalArguments:
  {{- range $i, $arg := .AdditionalArguments }}
  - "{{ printf "%s" . }}"
  {{- end }}
  {{- if .ServersTransportInsecureSkipVerify }}
  - "--serversTransport.insecureSkipVerify"
  {{- end }}
  {{- if .ForwardedHeaders }}
  {{- if .ForwardedHeadersInsecure }}
  - "--entrypoints.websecure.forwardedHeaders.insecure"
  {{- end }}
  {{- if .ForwardedHeadersTrustedIPs }}
  - "--entrypoints.websecure.forwardedHeaders.trustedIPs=127.0.0.1/32,{{ .ForwardedHeadersTrustedIPs }}"
  - "--entrypoints.web.forwardedHeaders.trustedIPs=127.0.0.1/32,{{ .ForwardedHeadersTrustedIPs }}"
  {{- end }}
  {{- end }}
  {{- if .ProxyProtocol }}
  {{- if .ProxyProtocolInsecure }}
  - "--entrypoints.websecure.proxyProtocol.insecure"
  {{- end }}
  {{- if .ProxyProtocolTrustedIPs }}
  - "--entrypoints.websecure.proxyProtocol.trustedIPs=127.0.0.1/32,{{ .ProxyProtocolTrustedIPs }}"
  {{- end }}
  {{- end }}
  {{- if .DnsChallengeEnabled }}
  - "--certificatesresolvers.{{ .DnsResolver }}-staging.acme.dnschallenge=true"
  - "--certificatesresolvers.{{ .DnsResolver }}-staging.acme.dnschallenge.provider={{ .DnsProvider }}"
  - "--certificatesresolvers.{{ .DnsResolver }}-staging.acme.dnschallenge.delayBeforeCheck=10"
  - "--certificatesresolvers.{{ .DnsResolver }}-staging.acme.email={{ .DnsResolverEmail }}"
  - "--certificatesresolvers.{{ .DnsResolver }}-staging.acme.storage=/data/acme.json"
  - "--certificatesresolvers.{{ .DnsResolver }}-staging.acme.caserver=https://acme-staging-v02.api.letsencrypt.org/directory"
  - "--certificatesresolvers.{{ .DnsResolver }}.acme.dnschallenge=true"
  - "--certificatesresolvers.{{ .DnsResolver }}.acme.dnschallenge.provider={{ .DnsProvider }}"
  - "--certificatesresolvers.{{ .DnsResolver }}.acme.dnschallenge.delayBeforeCheck=10"
  - "--certificatesresolvers.{{ .DnsResolver }}.acme.email={{ .DnsResolverEmail }}"
  - "--certificatesresolvers.{{ .DnsResolver }}.acme.storage=/data/acme.json"
  - "--certificatesresolvers.{{ .DnsResolver }}.acme.caserver=https://acme-v02.api.letsencrypt.org/directory"
  {{- if .DnsResolverIPs }}
  - "--certificatesresolvers.{{ .DnsResolver }}-staging.acme.dnschallenge.resolvers={{ .DnsResolverIPs }}"
  - "--certificatesresolvers.{{ .DnsResolver }}.acme.dnschallenge.resolvers={{ .DnsResolverIPs }}"
  {{- end }}
  {{- end }}
ports:
  web:
    redirectTo: websecure
  websecure:
    tls:
      enabled: true
      {{- if .DnsChallengeEnabled }}
      certResolver: {{ .DnsResolver }}
      {{- end }}

persistence:
  enabled: true
  accessMode: ReadWriteOnce
  size: 128Mi
  path: /data
  annotations: { }

ingressRoute:
  dashboard:
    enabled: {{ .EnableDashboard }}

logs:
  general:
  {{- if .DebugLog }}
    level: DEBUG
  {{- else }}
    level: INFO
  {{- end }}
  access:
    enabled: {{ .EnableAccessLog }}
pilot:
  enabled: false

{{- if .IngressProvider }}
providers:
  kubernetesCRD:
    enabled: true
    ingressClass: {{ .IngressProvider }}
{{- end }}

deployment:
  initContainers:
    - name: volume-permissions
      image: busybox:1.31.1
      command: ["sh", "-c", "touch /data/acme.json; chmod -Rv 0600 /data/acme.json; cat /data/acme.json"]
      volumeMounts:
        - name: data
          mountPath: /data

{{- if .DnsChallengeEnabled }}
envFrom:
  - secretRef:
      name: traefik-dns-provider-credentials
{{- end }}
`

type DefaultCertificateValues struct {
	Enabled                  bool
	Base64EncodedCertificate struct {
		Crt string
		Key string
	}

	Namespace string
}

var defaultTlsStoreTmpl = `
apiVersion: traefik.io/v1alpha1
kind: TLSStore
metadata:
  name: default
  namespace: {{ .Namespace }}

spec:
  defaultCertificate:
    secretName: default-certificate
`

var defaultCertificateSecretTmpl = `

---
apiVersion: v1
kind: Secret
metadata:
  name: default-certificate
  namespace: {{ .Namespace }}
type: Opaque
data:
  tls.crt: {{ .Base64EncodedCertificate.Crt }}
  tls.key: {{ .Base64EncodedCertificate.Key }}
`
