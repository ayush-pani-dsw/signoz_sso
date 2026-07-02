package ssotypes

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/SigNoz/signoz/pkg/query-service/constants"
	"golang.org/x/oauth2"
)

// SSOIdentity contains details of user received from SSO provider
type SSOIdentity struct {
	UserID            string
	Username          string
	PreferredUsername string
	Email             string
	EmailVerified     bool
	ConnectorData     []byte
}

// OAuthCallbackProvider is an interface implemented by connectors which use an OAuth
// style redirect flow to determine user information.
type OAuthCallbackProvider interface {
	// The initial URL user would be redirect to.
	// OAuth2 implementations support various scopes but we only need profile and user as
	// the roles are still being managed in SigNoz.
	BuildAuthURL(state string) (string, error)

	// Handle the callback to the server (after login at oauth provider site)
	// and return a email identity.
	// At the moment we dont support auto signup flow (based on domain), so
	// the full identity (including name, group etc) is not required outside of the
	// connector
	HandleCallback(r *http.Request) (identity *SSOIdentity, err error)
}

type SamlConfig struct {
	SamlEntity string `json:"samlEntity"`
	SamlIdp    string `json:"samlIdp"`
	SamlCert   string `json:"samlCert"`
}

// GoogleOauthConfig contains a generic config to support oauth
type GoogleOAuthConfig struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectURI"`
}

var googleIssuerURL = constants.GetOrDefaultEnv("SIGNOZ_OIDC_ISSUER_URL", "https://accounts.google.com")

func (g *GoogleOAuthConfig) GetProvider(domain string, siteUrl *url.URL) (OAuthCallbackProvider, error) {

	ctx, cancel := context.WithCancel(context.Background())

	provider, err := oidc.NewProvider(ctx, googleIssuerURL)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	// default to email and profile scope as we just use google auth
	// to verify identity and start a session.
	scopes := []string{"email"}

	// this is the url google will call after login completion
	redirectURL := fmt.Sprintf("%s://%s/%s",
		siteUrl.Scheme,
		siteUrl.Host,
		"api/v1/complete/google")
	
	// Environment variable overrides for dynamic server/deployment configuration
	clientID := constants.GetOrDefaultEnv("SIGNOZ_OIDC_CLIENT_ID", g.ClientID)
	clientSecret := constants.GetOrDefaultEnv("SIGNOZ_OIDC_CLIENT_SECRET", g.ClientSecret)
	redirectURL = constants.GetOrDefaultEnv("SIGNOZ_OIDC_REDIRECT_URL", redirectURL)

	return &GoogleOAuthProvider{
		RedirectURI: g.RedirectURI,
		OAuth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
			RedirectURL:  redirectURL,
		},
		Verifier: provider.Verifier(
			&oidc.Config{ClientID: clientID},
		),
		Cancel:       cancel,
		HostedDomain: domain,
	}, nil
}
