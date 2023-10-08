package helm

import (
	"context"
	"fmt"
	"github.com/zcubbs/x/pretty"
	"gopkg.in/yaml.v2"
	"helm.sh/helm/v3/pkg/cli"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
	"github.com/pkg/errors"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli/values"
	"helm.sh/helm/v3/pkg/downloader"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
	"helm.sh/helm/v3/pkg/strvals"
)

type Client struct {
	Settings *cli.EnvSettings
}

func NewClient() *Client {
	return &Client{
		Settings: cli.New(),
	}
}

// RepoAdd adds repo with given name and url
func (c *Client) RepoAdd(name, url string) error {
	repoFile := c.Settings.RepositoryConfig

	//Ensure the file directory exists as it is required for file locking
	err := os.MkdirAll(filepath.Dir(repoFile), os.ModePerm)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create directory %s: %w", filepath.Dir(repoFile), err)
	}

	// Acquire a file lock for process synchronization
	fileLock := flock.New(strings.Replace(repoFile, filepath.Ext(repoFile), ".lock", 1))
	lockCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	locked, err := fileLock.TryLockContext(lockCtx, time.Second)
	if err == nil && locked {
		defer func(fileLock *flock.Flock) {
			err := fileLock.Unlock()
			if err != nil {
				log.Fatal(err)
			}
		}(fileLock)
	}
	if err != nil {
		return fmt.Errorf("failed to lock file %s: %w", fileLock, err)
	}

	b, err := os.ReadFile(repoFile)
	if err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}

	var f repo.File
	if err := yaml.Unmarshal(b, &f); err != nil {
		log.Fatal(err)
	}

	if f.Has(name) {
		// repo already exists
		return nil
	}

	clt := repo.Entry{
		Name: name,
		URL:  url,
	}

	r, err := repo.NewChartRepository(&clt, getter.All(c.Settings))
	if err != nil {
		return fmt.Errorf("failed to create chart repository: %w", err)
	}

	if _, err := r.DownloadIndexFile(); err != nil {
		err := errors.Wrapf(err, "looks like %q is not a valid chart repository or cannot be reached", url)
		return fmt.Errorf("failed to download index file: %w", err)
	}

	f.Update(&clt)

	if err := f.WriteFile(repoFile, 0644); err != nil {
		return fmt.Errorf("failed to write repository file: %w", err)
	}

	return nil
}

// RepoUpdate updates charts for all helm repos
func (c *Client) RepoUpdate() error {
	repoFile := c.Settings.RepositoryConfig

	f, err := repo.LoadFile(repoFile)
	if os.IsNotExist(errors.Cause(err)) || len(f.Repositories) == 0 {
		return errors.New("no repositories found. You must add one before updating")
	}
	var repos []*repo.ChartRepository
	for _, cfg := range f.Repositories {
		r, err := repo.NewChartRepository(cfg, getter.All(c.Settings))
		if err != nil {
			return fmt.Errorf("failed to create chart repository: %w", err)
		}
		repos = append(repos, r)
	}

	fmt.Printf("Hang tight while we grab the latest from your chart repositories...\n")
	var wg sync.WaitGroup
	for _, re := range repos {
		wg.Add(1)
		go func(re *repo.ChartRepository) {
			defer wg.Done()
			if _, err := re.DownloadIndexFile(); err != nil {
				fmt.Printf("...Unable to get an update from the %q chart repository (%s):\n\t%s\n", re.Config.Name, re.Config.URL, err)
			} else {
				fmt.Printf("...Successfully got an update from the %q chart repository\n", re.Config.Name)
			}
		}(re)
	}
	wg.Wait()
	fmt.Printf("Update Complete. ⎈ Happy Helming!⎈\n")

	return nil
}

// InstallChart installs a helm chart
func (c *Client) InstallChart(name, repo, chart string, args map[string]string) error {
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(
		c.Settings.RESTClientGetter(),
		c.Settings.Namespace(),
		os.Getenv("HELM_DRIVER"), debug); err != nil {
		return fmt.Errorf("failed to initialize helm action configuration: %w", err)
	}
	client := action.NewInstall(actionConfig)

	if client.Version == "" && client.Devel {
		client.Version = ">0.0.0-0"
	}
	//name, chart, err := client.NameAndChart(args)
	client.ReleaseName = name
	cp, err := client.ChartPathOptions.
		LocateChart(fmt.Sprintf("%s/%s", repo, chart), c.Settings)
	if err != nil {
		return fmt.Errorf("failed to locate chart: %w", err)
	}

	debug("CHART PATH: %s\n", cp)

	p := getter.All(c.Settings)
	valueOpts := &values.Options{}
	vals, err := valueOpts.MergeValues(p)
	if err != nil {
		return fmt.Errorf("failed to merge values: %w", err)
	}

	// Add args
	if err := strvals.ParseInto(args["set"], vals); err != nil {
		return errors.Wrap(err, "failed parsing --set data")
	}

	// Check chart dependencies to make sure all are present in /charts
	chartRequested, err := loader.Load(cp)
	if err != nil {
		return fmt.Errorf("failed to load chart: %w", err)
	}

	validInstallableChart, err := isChartInstallable(chartRequested)
	if !validInstallableChart {
		return fmt.Errorf("chart is not installable: %w", err)
	}

	if req := chartRequested.Metadata.Dependencies; req != nil {
		// If CheckDependencies returns an error, we have unfulfilled dependencies.
		// As of Helm 2.4.0, this is treated as a stopping condition:
		// https://github.com/helm/helm/issues/2209
		if err := action.CheckDependencies(chartRequested, req); err != nil {
			if client.DependencyUpdate {
				man := &downloader.Manager{
					Out:              os.Stdout,
					ChartPath:        cp,
					Keyring:          client.ChartPathOptions.Keyring,
					SkipUpdate:       false,
					Getters:          p,
					RepositoryConfig: c.Settings.RepositoryConfig,
					RepositoryCache:  c.Settings.RepositoryCache,
				}
				if err := man.Update(); err != nil {
					return fmt.Errorf("failed to update dependencies: %w", err)
				}
			} else {
				return fmt.Errorf("failed to check dependencies: %w", err)
			}
		}
	}

	client.Namespace = c.Settings.Namespace()
	release, err := client.Run(chartRequested, vals)
	if err != nil {
		return fmt.Errorf("failed to install chart: %w", err)
	}

	if c.Settings.Debug {
		pretty.PrintJson(release.Manifest)
	}

	return nil
}

// UninstallChart uninstalls a helm chart
func (c *Client) UninstallChart(name string) error {
	actionConfig := new(action.Configuration)
	if err := actionConfig.Init(
		c.Settings.RESTClientGetter(),
		c.Settings.Namespace(),
		os.Getenv("HELM_DRIVER"), debug); err != nil {
		return fmt.Errorf("failed to initialize helm action configuration: %w", err)
	}
	client := action.NewUninstall(actionConfig)

	_, err := client.Run(name)
	if err != nil {
		return fmt.Errorf("failed to uninstall chart: %w", err)
	}

	return nil
}

func isChartInstallable(ch *chart.Chart) (bool, error) {
	switch ch.Metadata.Type {
	case "", "application":
		return true, nil
	}
	return false, errors.Errorf("%s charts are not installable", ch.Metadata.Type)
}

func debug(format string, v ...interface{}) {
	format = fmt.Sprintf("[debug] %s\n", format)
	err := log.Output(2, fmt.Sprintf(format, v...))
	if err != nil {
		fmt.Printf("error: %s", err)
	}
}
