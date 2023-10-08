package helm

import (
	"fmt"
	helmValues "helm.sh/helm/v3/pkg/cli/values"
)

func convertMapToChartValues(input map[string]interface{}) helmValues.Options {
	var sets []string
	recursiveBuildSets(input, "", &sets)

	return helmValues.Options{
		Values: sets,
	}
}

func recursiveBuildSets(input map[string]interface{}, parentKey string, sets *[]string) {
	for key, value := range input {
		if castedValue, ok := value.(map[string]interface{}); ok {
			// If value is another map, recursively handle it
			if parentKey == "" {
				recursiveBuildSets(castedValue, key, sets)
			} else {
				recursiveBuildSets(castedValue, fmt.Sprintf("%s.%s", parentKey, key), sets)
			}
		} else {
			// Else, add to the set slice
			setValue := fmt.Sprintf("%s=%v", key, value)
			if parentKey != "" {
				setValue = fmt.Sprintf("%s.%s=%v", parentKey, key, value)
			}
			*sets = append(*sets, setValue)
		}
	}
}
