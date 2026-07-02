package routerweb

import (
	"strings"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/http/middleware"
	"github.com/SigNoz/signoz/pkg/web"
	"github.com/gorilla/mux"
)

const (
	indexFileName string = "index.html"
)

type provider struct {
	config web.Config
}

func NewFactory() factory.ProviderFactory[web.Web, web.Config] {
	return factory.NewProviderFactory(factory.MustNewName("router"), New)
}

func New(ctx context.Context, settings factory.ProviderSettings, config web.Config) (web.Web, error) {
	fi, err := os.Stat(config.Directory)
	if err != nil {
		return nil, fmt.Errorf("cannot access web directory: %w", err)
	}

	ok := fi.IsDir()
	if !ok {
		return nil, fmt.Errorf("web directory is not a directory")
	}

	fi, err = os.Stat(filepath.Join(config.Directory, indexFileName))
	if err != nil {
		return nil, fmt.Errorf("cannot access %q in web directory: %w", indexFileName, err)
	}

	if os.IsNotExist(err) || fi.IsDir() {
		return nil, fmt.Errorf("%q does not exist", indexFileName)
	}

	return &provider{
		config: config,
	}, nil
}

func (provider *provider) AddToRouter(router *mux.Router) error {
	cache := middleware.NewCache(0)
	err := router.PathPrefix(provider.config.Prefix).
		Handler(
			http.StripPrefix(
				provider.config.Prefix,
				cache.Wrap(http.HandlerFunc(provider.ServeHTTP)),
			),
		).GetError()
	if err != nil {
		return fmt.Errorf("unable to add web to router: %w", err)
	}

	return nil
}

func (provider *provider) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Join internally call path.Clean to prevent directory traversal
	path := filepath.Join(provider.config.Directory, req.URL.Path)

	// check whether a file exists or is a directory at the given path
	fi, err := os.Stat(path)
	if os.IsNotExist(err) || fi.IsDir() {
		// file does not exist or path is a directory, serve index.html with auto-redirect script injected
		indexPath := filepath.Join(provider.config.Directory, indexFileName)
		content, readErr := os.ReadFile(indexPath)
		if readErr != nil {
			http.ServeFile(rw, req, indexPath)
			return
		}
		
		script := `<script>(function(){var t=localStorage.getItem("AUTH_TOKEN");if(t)return;var p=new URLSearchParams(window.location.search);if(p.get("password")==="Y"||p.get("ssoerror")||p.get("jwt"))return;var path=window.location.pathname;if(path.endsWith("/login")||path.endsWith("/login/")||path==="/"||path.endsWith("/log-aggregator")||path.endsWith("/log-aggregator/")){window.location.href="/api/v1/auth/sso/auto-redirect?source="+encodeURIComponent(window.location.href);}})();</script>`
		
		htmlStr := string(content)
		htmlStr = strings.Replace(htmlStr, "<head>", "<head>"+script, 1)
		
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Write([]byte(htmlStr))
		return
	}

	if err != nil {
		// if we got an error (that wasn't that the file doesn't exist) stating the
		// file, return a 500 internal server error and stop
		// TODO: Put down a crash html page here
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	// otherwise, use http.FileServer to serve the static file
	http.FileServer(http.Dir(provider.config.Directory)).ServeHTTP(rw, req)
}
