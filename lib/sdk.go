package vulmap

import (
	"bufio"
	"bytes"
	"io"

	"github.com/khulnasoft-lab/httpx/common/httpx"
	"github.com/khulnasoft-lab/vulmap/pkg/catalog/disk"
	"github.com/khulnasoft-lab/vulmap/pkg/catalog/loader"
	"github.com/khulnasoft-lab/vulmap/pkg/core"
	"github.com/khulnasoft-lab/vulmap/pkg/core/inputs"
	"github.com/khulnasoft-lab/vulmap/pkg/output"
	"github.com/khulnasoft-lab/vulmap/pkg/parsers"
	"github.com/khulnasoft-lab/vulmap/pkg/progress"
	"github.com/khulnasoft-lab/vulmap/pkg/protocols"
	"github.com/khulnasoft-lab/vulmap/pkg/protocols/common/hosterrorscache"
	"github.com/khulnasoft-lab/vulmap/pkg/protocols/common/interactsh"
	"github.com/khulnasoft-lab/vulmap/pkg/protocols/headless/engine"
	"github.com/khulnasoft-lab/vulmap/pkg/reporting"
	"github.com/khulnasoft-lab/vulmap/pkg/templates"
	"github.com/khulnasoft-lab/vulmap/pkg/templates/signer"
	"github.com/khulnasoft-lab/vulmap/pkg/types"
	"github.com/khulnasoft-lab/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/khulnasoft-lab/utils/errors"
)

// VulmapSDKOptions contains options for vulmap SDK
type VulmapSDKOptions func(e *VulmapEngine) error

var (
	// ErrNotImplemented is returned when a feature is not implemented
	ErrNotImplemented = errorutil.New("Not implemented")
	// ErrNoTemplatesAvailable is returned when no templates are available to execute
	ErrNoTemplatesAvailable = errorutil.New("No templates available")
	// ErrNoTargetsAvailable is returned when no targets are available to scan
	ErrNoTargetsAvailable = errorutil.New("No targets available")
	// ErrOptionsNotSupported is returned when an option is not supported in thread safe mode
	ErrOptionsNotSupported = errorutil.NewWithFmt("Option %v not supported in thread safe mode")
)

type engineMode uint

const (
	singleInstance engineMode = iota
	threadSafe
)

// VulmapEngine is the Engine/Client for vulmap which
// runs scans using templates and returns results
type VulmapEngine struct {
	// user options
	resultCallbacks             []func(event *output.ResultEvent)
	onFailureCallback           func(event *output.InternalEvent)
	disableTemplatesAutoUpgrade bool
	enableStats                 bool
	onUpdateAvailableCallback   func(newVersion string)

	// ready-status fields
	templatesLoaded bool

	// unexported core fields
	interactshClient *interactsh.Client
	catalog          *disk.DiskCatalog
	rateLimiter      *ratelimit.Limiter
	store            *loader.Store
	httpxClient      *httpx.HTTPX
	inputProvider    *inputs.SimpleInputProvider
	engine           *core.Engine
	mode             engineMode
	browserInstance  *engine.Browser
	httpClient       *retryablehttp.Client

	// unexported meta options
	opts           *types.Options
	interactshOpts *interactsh.Options
	hostErrCache   *hosterrorscache.Cache
	customWriter   output.Writer
	customProgress progress.Progress
	rc             reporting.Client
	executerOpts   protocols.ExecutorOptions
}

// LoadAllTemplates loads all vulmap template based on given options
func (e *VulmapEngine) LoadAllTemplates() error {
	workflowLoader, err := parsers.NewLoader(&e.executerOpts)
	if err != nil {
		return errorutil.New("Could not create workflow loader: %s\n", err)
	}
	e.executerOpts.WorkflowLoader = workflowLoader

	e.store, err = loader.New(loader.NewConfig(e.opts, e.catalog, e.executerOpts))
	if err != nil {
		return errorutil.New("Could not create loader client: %s\n", err)
	}
	e.store.Load()
	return nil
}

// GetTemplates returns all vulmap templates that are loaded
func (e *VulmapEngine) GetTemplates() []*templates.Template {
	if !e.templatesLoaded {
		_ = e.LoadAllTemplates()
	}
	return e.store.Templates()
}

// LoadTargets(urls/domains/ips only) adds targets to the vulmap engine
func (e *VulmapEngine) LoadTargets(targets []string, probeNonHttp bool) {
	for _, target := range targets {
		if probeNonHttp {
			e.inputProvider.SetWithProbe(target, e.httpxClient)
		} else {
			e.inputProvider.Set(target)
		}
	}
}

// LoadTargetsFromReader adds targets(urls/domains/ips only) from reader to the vulmap engine
func (e *VulmapEngine) LoadTargetsFromReader(reader io.Reader, probeNonHttp bool) {
	buff := bufio.NewScanner(reader)
	for buff.Scan() {
		if probeNonHttp {
			e.inputProvider.SetWithProbe(buff.Text(), e.httpxClient)
		} else {
			e.inputProvider.Set(buff.Text())
		}
	}
}

// GetExecuterOptions returns the vulmap executor options
func (e *VulmapEngine) GetExecuterOptions() *protocols.ExecutorOptions {
	return &e.executerOpts
}

// ParseTemplate parses a template from given data
// template verification status can be accessed from template.Verified
func (e *VulmapEngine) ParseTemplate(data []byte) (*templates.Template, error) {
	return templates.ParseTemplateFromReader(bytes.NewReader(data), nil, e.executerOpts)
}

// SignTemplate signs the tempalate using given signer
func (e *VulmapEngine) SignTemplate(tmplSigner *signer.TemplateSigner, data []byte) ([]byte, error) {
	tmpl, err := e.ParseTemplate(data)
	if err != nil {
		return data, err
	}
	if tmpl.Verified {
		// already signed
		return data, nil
	}
	if len(tmpl.Workflows) > 0 {
		return data, templates.ErrNotATemplate
	}
	signatureData, err := tmplSigner.Sign(data, tmpl)
	if err != nil {
		return data, err
	}
	buff := bytes.NewBuffer(signer.RemoveSignatureFromData(data))
	buff.WriteString("\n" + signatureData)
	return buff.Bytes(), err
}

// Close all resources used by vulmap engine
func (e *VulmapEngine) Close() {
	e.interactshClient.Close()
	e.rc.Close()
	e.customWriter.Close()
	e.hostErrCache.Close()
	e.executerOpts.RateLimiter.Stop()
}

// ExecuteWithCallback executes templates on targets and calls callback on each result(only if results are found)
func (e *VulmapEngine) ExecuteWithCallback(callback ...func(event *output.ResultEvent)) error {
	if !e.templatesLoaded {
		_ = e.LoadAllTemplates()
	}
	if len(e.store.Templates()) == 0 && len(e.store.Workflows()) == 0 {
		return ErrNoTemplatesAvailable
	}
	if e.inputProvider.Count() == 0 {
		return ErrNoTargetsAvailable
	}

	filtered := []func(event *output.ResultEvent){}
	for _, callback := range callback {
		if callback != nil {
			filtered = append(filtered, callback)
		}
	}
	e.resultCallbacks = append(e.resultCallbacks, filtered...)

	_ = e.engine.ExecuteScanWithOpts(e.store.Templates(), e.inputProvider, false)
	defer e.engine.WorkPool().Wait()
	return nil
}

// NewVulmapEngine creates a new vulmap engine instance
func NewVulmapEngine(options ...VulmapSDKOptions) (*VulmapEngine, error) {
	// default options
	e := &VulmapEngine{
		opts: types.DefaultOptions(),
		mode: singleInstance,
	}
	for _, option := range options {
		if err := option(e); err != nil {
			return nil, err
		}
	}
	if err := e.init(); err != nil {
		return nil, err
	}
	return e, nil
}
