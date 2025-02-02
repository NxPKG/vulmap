# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v
# This should be disabled if the binary uses pprof
LDFLAGS := -s -w

ifneq ($(shell go env GOOS),darwin)
LDFLAGS := -extldflags "-static"
endif
    
all: build
build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "vulmap" cmd/vulmap/main.go
docs:
	if ! which dstdocgen > /dev/null; then
		echo -e "Command not found! Install? (y/n) \c"
		go get -v github.com/projectdiscovery/yamldoc-go/cmd/docgen/dstdocgen
	fi
	$(GOCMD) generate pkg/templates/templates.go
	$(GOBUILD) -o "cmd/docgen/docgen" cmd/docgen/docgen.go
	./cmd/docgen/docgen docs.md vulmap-jsonschema.json
test:
	$(GOTEST) $(GOFLAGS) ./...
integration:
	cd integration_tests; bash run.sh
functional:
	cd cmd/functional-test; bash run.sh
tidy:
	$(GOMOD) tidy
devtools:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "bindgen" pkg/js/devtools/bindgen/cmd/bindgen/main.go
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "jsdocgen" pkg/js/devtools/jsdocgen/main.go
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "scrapefuncs" pkg/js/devtools/scrapefuncs/main.go