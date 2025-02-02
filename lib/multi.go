package vulmap

import (
	"context"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/khulnasoft-lab/vulmap/pkg/catalog/loader"
	"github.com/khulnasoft-lab/vulmap/pkg/core"
	"github.com/khulnasoft-lab/vulmap/pkg/core/inputs"
	"github.com/khulnasoft-lab/vulmap/pkg/output"
	"github.com/khulnasoft-lab/vulmap/pkg/parsers"
	"github.com/khulnasoft-lab/vulmap/pkg/protocols"
	"github.com/khulnasoft-lab/vulmap/pkg/protocols/common/contextargs"
	"github.com/khulnasoft-lab/vulmap/pkg/types"
	"github.com/khulnasoft-lab/ratelimit"
	errorutil "github.com/khulnasoft-lab/utils/errors"
)

// unsafeOptions are those vulmap objects/instances/types
// that are required to run vulmap engine but are not thread safe
// hence they are ephemeral and are created on every ExecuteVulmapWithOpts invocation
// in ThreadSafeVulmapEngine
type unsafeOptions struct {
	executerOpts protocols.ExecutorOptions
	engine       *core.Engine
}

// createEphemeralObjects creates ephemeral vulmap objects/instances/types
func createEphemeralObjects(base *VulmapEngine, opts *types.Options) (*unsafeOptions, error) {
	u := &unsafeOptions{}
	u.executerOpts = protocols.ExecutorOptions{
		Output:          base.customWriter,
		Options:         opts,
		Progress:        base.customProgress,
		Catalog:         base.catalog,
		IssuesClient:    base.rc,
		RateLimiter:     base.rateLimiter,
		Interactsh:      base.interactshClient,
		HostErrorsCache: base.hostErrCache,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
	}
	if opts.RateLimitMinute > 0 {
		u.executerOpts.RateLimiter = ratelimit.New(context.Background(), uint(opts.RateLimitMinute), time.Minute)
	} else if opts.RateLimit > 0 {
		u.executerOpts.RateLimiter = ratelimit.New(context.Background(), uint(opts.RateLimit), time.Second)
	} else {
		u.executerOpts.RateLimiter = ratelimit.NewUnlimited(context.Background())
	}
	u.engine = core.New(opts)
	u.engine.SetExecuterOptions(u.executerOpts)
	return u, nil
}

// ThreadSafeVulmapEngine is a tweaked version of vulmap.Engine whose methods are thread-safe
// and can be used concurrently. Non-thread-safe methods start with Global prefix
type ThreadSafeVulmapEngine struct {
	eng *VulmapEngine
}

// NewThreadSafeVulmapEngine creates a new vulmap engine with given options
// whose methods are thread-safe and can be used concurrently
// Note: Non-thread-safe methods start with Global prefix
func NewThreadSafeVulmapEngine(opts ...VulmapSDKOptions) (*ThreadSafeVulmapEngine, error) {
	// default options
	e := &VulmapEngine{
		opts: types.DefaultOptions(),
		mode: threadSafe,
	}
	for _, option := range opts {
		if err := option(e); err != nil {
			return nil, err
		}
	}
	if err := e.init(); err != nil {
		return nil, err
	}
	return &ThreadSafeVulmapEngine{eng: e}, nil
}

// GlobalLoadAllTemplates loads all templates from vulmap-templates repo
// This method will load all templates based on filters given at the time of vulmap engine creation in opts
func (e *ThreadSafeVulmapEngine) GlobalLoadAllTemplates() error {
	return e.eng.LoadAllTemplates()
}

// GlobalResultCallback sets a callback function which will be called for each result
func (e *ThreadSafeVulmapEngine) GlobalResultCallback(callback func(event *output.ResultEvent)) {
	e.eng.resultCallbacks = []func(*output.ResultEvent){callback}
}

// ExecuteWithCallback executes templates on targets and calls callback on each result(only if results are found)
// This method can be called concurrently and it will use some global resources but can be runned parllely
// by invoking this method with different options and targets
// Note: Not all options are thread-safe. this method will throw error if you try to use non-thread-safe options
func (e *ThreadSafeVulmapEngine) ExecuteVulmapWithOpts(targets []string, opts ...VulmapSDKOptions) error {
	baseOpts := *e.eng.opts
	tmpEngine := &VulmapEngine{opts: &baseOpts, mode: threadSafe}
	for _, option := range opts {
		if err := option(tmpEngine); err != nil {
			return err
		}
	}
	// create ephemeral vulmap objects/instances/types using base vulmap engine
	unsafeOpts, err := createEphemeralObjects(e.eng, tmpEngine.opts)
	if err != nil {
		return err
	}

	// load templates
	workflowLoader, err := parsers.NewLoader(&unsafeOpts.executerOpts)
	if err != nil {
		return errorutil.New("Could not create workflow loader: %s\n", err)
	}
	unsafeOpts.executerOpts.WorkflowLoader = workflowLoader

	store, err := loader.New(loader.NewConfig(tmpEngine.opts, e.eng.catalog, unsafeOpts.executerOpts))
	if err != nil {
		return errorutil.New("Could not create loader client: %s\n", err)
	}
	store.Load()

	inputProvider := &inputs.SimpleInputProvider{
		Inputs: []*contextargs.MetaInput{},
	}

	// load targets
	for _, target := range targets {
		inputProvider.Set(target)
	}

	if len(store.Templates()) == 0 && len(store.Workflows()) == 0 {
		return ErrNoTemplatesAvailable
	}
	if inputProvider.Count() == 0 {
		return ErrNoTargetsAvailable
	}

	engine := core.New(tmpEngine.opts)
	engine.SetExecuterOptions(unsafeOpts.executerOpts)

	_ = engine.ExecuteScanWithOpts(store.Templates(), inputProvider, false)

	engine.WorkPool().Wait()
	return nil
}

// Close all resources used by vulmap engine
func (e *ThreadSafeVulmapEngine) Close() {
	e.eng.Close()
}
