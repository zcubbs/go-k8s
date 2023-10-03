package certmanager

import (
	"context"
	"fmt"
	"github.com/zcubbs/go-k8s/helm"
	"github.com/zcubbs/go-k8s/kubernetes"
	"github.com/zcubbs/x/pretty"
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
	Version string

	LetsencryptIssuerEnabled        bool
	LetsencryptIssuerEmail          string
	LetsEncryptIngressClassResolver string
}

func Install(values Values, kubeconfig string, debug bool) error {
	if debug {
		pretty.PrintJson(values)
	}

	if err := validateValues(&values); err != nil {
		return err
	}

	vals := map[string]interface{}{
		"installCRDs": true,
	}

	err := helm.Install(helm.Chart{
		Name:            certmanagerChartName,
		Repo:            certmanagerHelmRepoName,
		URL:             certmanagerHelmRepoURL,
		Version:         values.Version,
		Values:          vals,
		ValuesFiles:     nil,
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
}

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
      name: issuer-account-key
    solvers:
      - http01:
          ingress:
            class: {{ .IngressClassResolver }}
`
