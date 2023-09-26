package kubernetes

import (
	"fmt"
	"github.com/zcubbs/x/bash"
	"github.com/zcubbs/x/yaml"
	"os"
	"time"
)

func ApplyManifest(manifestTmpl string, data interface{}, debug bool) error {
	b, err := yaml.ApplyTmpl(manifestTmpl, data, debug)
	if err != nil {
		return fmt.Errorf("failed to apply template \n %w", err)
	}

	// generate tmp file name
	fn := fmt.Sprintf("/tmp/tmpManifest_%s.yaml",
		time.Unix(time.Now().Unix(), 0).Format("20060102150405"),
	)

	// write tmp manifest
	err = os.WriteFile(fn, b, 0644)
	if err != nil {
		return fmt.Errorf("failed to write tmp manifest \n %w", err)
	}

	err = bash.ExecuteCmd("kubectl", debug, "apply", "-f", fn)
	if err != nil {
		return fmt.Errorf("failed to apply manifest \n %w", err)
	}

	// delete tmp manifest
	err = os.Remove(fn)
	if err != nil {
		return fmt.Errorf("failed to delete tmp manifest \n %w", err)
	}
	return nil
}
