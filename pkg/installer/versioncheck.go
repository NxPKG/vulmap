package installer

import (
	"encoding/json"
	"io"
	"net/url"
	"os"
	"runtime"
	"sync"

	"github.com/khulnasoft-lab/vulmap/pkg/catalog/config"
	"github.com/projectdiscovery/retryablehttp-go"
	updateutils "github.com/khulnasoft-lab/utils/update"
)

const (
	pdtmVulmapVersionEndpoint    = "https://api.pdtm.sh/api/v1/tools/nuclei"
	pdtmVulmapIgnoreFileEndpoint = "https://api.pdtm.sh/api/v1/tools/nuclei/ignore"
)

// defaultHttpClient is http client that is only meant to be used for version check
// if proxy env variables are set those are reflected in this client
var retryableHttpClient = retryablehttp.NewClient(retryablehttp.Options{HttpClient: updateutils.DefaultHttpClient, RetryMax: 2})

// PdtmAPIResponse is the response from pdtm API for vulmap endpoint
type PdtmAPIResponse struct {
	IgnoreHash string `json:"ignore-hash"`
	Tools      []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"tools"`
}

// VulmapVersionCheck checks for the latest version of vulmap and vulmap templates
// and returns an error if it fails to check on success it returns nil and changes are
// made to the default config in config.DefaultConfig
func VulmapVersionCheck() error {
	return doVersionCheck(false)
}

// this will be updated by features of 1.21 release (which directly provides sync.Once(func()))
type sdkUpdateCheck struct {
	sync.Once
}

var sdkUpdateCheckInstance = &sdkUpdateCheck{}

// VulmapSDKVersionCheck checks for latest version of vulmap which running in sdk mode
// this only happens once per process regardless of how many times this function is called
func VulmapSDKVersionCheck() {
	sdkUpdateCheckInstance.Do(func() {
		_ = doVersionCheck(true)
	})
}

// getpdtmParams returns encoded query parameters sent to update check endpoint
func getpdtmParams(isSDK bool) string {
	params := &url.Values{}
	params.Add("os", runtime.GOOS)
	params.Add("arch", runtime.GOARCH)
	params.Add("go_version", runtime.Version())
	params.Add("v", config.Version)
	if isSDK {
		params.Add("sdk", "true")
	}
	params.Add("utm_source", getUtmSource())
	return params.Encode()
}

// UpdateIgnoreFile updates default ignore file by downloading latest ignore file
func UpdateIgnoreFile() error {
	resp, err := retryableHttpClient.Get(pdtmVulmapIgnoreFileEndpoint + "?" + getpdtmParams(false))
	if err != nil {
		return err
	}
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := os.WriteFile(config.DefaultConfig.GetIgnoreFilePath(), bin, 0644); err != nil {
		return err
	}
	return config.DefaultConfig.UpdateVulmapIgnoreHash()
}

func doVersionCheck(isSDK bool) error {
	resp, err := retryableHttpClient.Get(pdtmVulmapVersionEndpoint + "?" + getpdtmParams(isSDK))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var pdtmResp PdtmAPIResponse
	if err := json.Unmarshal(bin, &pdtmResp); err != nil {
		return err
	}
	var vulmapversion, templateversion string
	for _, tool := range pdtmResp.Tools {
		switch tool.Name {
		case "vulmap":
			if tool.Version != "" {
				vulmapversion = "v" + tool.Version
			}

		case "vulmap-templates":
			if tool.Version != "" {
				templateversion = "v" + tool.Version
			}
		}
	}
	return config.DefaultConfig.WriteVersionCheckData(pdtmResp.IgnoreHash, vulmapversion, templateversion)
}
