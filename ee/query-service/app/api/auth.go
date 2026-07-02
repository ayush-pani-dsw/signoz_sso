package api

import (
	"github.com/SigNoz/signoz/pkg/types"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"go.uber.org/zap"

	"github.com/SigNoz/signoz/pkg/query-service/constants"
	"github.com/SigNoz/signoz/pkg/valuer"
)

func handleSsoError(w http.ResponseWriter, r *http.Request, redirectURL string) {
	ssoError := []byte("Login failed. Please contact your system administrator")
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(ssoError)))
	base64.StdEncoding.Encode(dst, ssoError)

	http.Redirect(w, r, fmt.Sprintf("%s?ssoerror=%s", redirectURL, string(dst)), http.StatusSeeOther)
}

// receiveSAML completes a SAML request and gets user logged in
func (ah *APIHandler) receiveSAML(w http.ResponseWriter, r *http.Request) {
	// this is the source url that initiated the login request
	redirectUri := constants.GetDefaultSiteURL()
	ctx := context.Background()

	err := r.ParseForm()
	if err != nil {
		zap.L().Error("[receiveSAML] failed to process response - invalid response from IDP", zap.Error(err), zap.Any("request", r))
		handleSsoError(w, r, redirectUri)
		return
	}

	// the relay state is sent when a login request is submitted to
	// Idp.
	relayState := r.FormValue("RelayState")
	zap.L().Debug("[receiveML] relay state", zap.String("relayState", relayState))

	parsedState, err := url.Parse(relayState)
	if err != nil || relayState == "" {
		zap.L().Error("[receiveSAML] failed to process response - invalid response from IDP", zap.Error(err), zap.Any("request", r))
		handleSsoError(w, r, redirectUri)
		return
	}

	// upgrade redirect url from the relay state for better accuracy
	redirectUri = fmt.Sprintf("%s://%s%s", parsedState.Scheme, parsedState.Host, parsedState.Path)

	// fetch domain by parsing relay state.
	domain, err := ah.Signoz.Modules.User.GetDomainFromSsoResponse(ctx, parsedState)
	if err != nil {
		handleSsoError(w, r, redirectUri)
		return
	}

	orgID, err := valuer.NewUUID(domain.OrgID)
	if err != nil {
		handleSsoError(w, r, redirectUri)
		return
	}
	_ = orgID

	// Bypassed license check for self-hosted deployment
	// _, err = ah.Signoz.Licensing.GetActive(ctx, orgID)
	// if err != nil {
	// 	zap.L().Error("[receiveSAML] sso requested but feature unavailable in org domain")
	// 	http.Redirect(w, r, fmt.Sprintf("%s?ssoerror=%s", redirectUri, "feature unavailable, please upgrade your billing plan to access this feature"), http.StatusMovedPermanently)
	// 	return
	// }

	sp, err := domain.PrepareSamlRequest(parsedState)
	if err != nil {
		zap.L().Error("[receiveSAML] failed to prepare saml request for domain", zap.String("domain", domain.String()), zap.Error(err))
		handleSsoError(w, r, redirectUri)
		return
	}

	assertionInfo, err := sp.RetrieveAssertionInfo(r.FormValue("SAMLResponse"))
	if err != nil {
		zap.L().Error("[receiveSAML] failed to retrieve assertion info from  saml response", zap.String("domain", domain.String()), zap.Error(err))
		handleSsoError(w, r, redirectUri)
		return
	}

	if assertionInfo.WarningInfo.InvalidTime {
		zap.L().Error("[receiveSAML] expired saml response", zap.String("domain", domain.String()), zap.Error(err))
		handleSsoError(w, r, redirectUri)
		return
	}

	email := assertionInfo.NameID
	if email == "" {
		zap.L().Error("[receiveSAML] invalid email in the SSO response", zap.String("domain", domain.String()))
		handleSsoError(w, r, redirectUri)
		return
	}

	nextPage, err := ah.Signoz.Modules.User.PrepareSsoRedirect(ctx, redirectUri, email)
	if err != nil {
		zap.L().Error("[receiveSAML] failed to generate redirect URI after successful login ", zap.String("domain", domain.String()), zap.Error(err))
		handleSsoError(w, r, redirectUri)
		return
	}

	http.Redirect(w, r, nextPage, http.StatusSeeOther)
}

func (ah *APIHandler) autoRedirectSAML(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Query the first SSO-enabled domain
	var stored []types.StorableOrgDomain
	err := ah.Signoz.SQLStore.BunDB().NewSelect().
		Model(&stored).
		Limit(1).
		Scan(ctx)
		
	if err != nil || len(stored) == 0 {
		zap.L().Error("[autoRedirectSAML] failed to list domains or no domain found", zap.Error(err))
		http.Redirect(w, r, "/login?password=Y", http.StatusSeeOther)
		return
	}
	
	gettableDomain := &types.GettableOrgDomain{StorableOrgDomain: stored[0]}
	if err := gettableDomain.LoadConfig(stored[0].Data); err != nil || !gettableDomain.SsoEnabled {
		zap.L().Error("[autoRedirectSAML] domain SSO not enabled or failed to load config")
		http.Redirect(w, r, "/login?password=Y", http.StatusSeeOther)
		return
	}
	
	sourceUrl := r.URL.Query().Get("source")
	if sourceUrl == "" {
		sourceUrl = constants.GetDefaultSiteURL()
	}
	escapedUrl, _ := url.QueryUnescape(sourceUrl)
	siteUrl, err := url.Parse(escapedUrl)
	if err != nil {
		siteUrl, _ = url.Parse(constants.GetDefaultSiteURL())
	}
	
	ssoUrl, err := gettableDomain.BuildSsoUrl(siteUrl)
	if err != nil {
		zap.L().Error("[autoRedirectSAML] failed to build SSO URL", zap.Error(err))
		http.Redirect(w, r, "/login?password=Y", http.StatusSeeOther)
		return
	}
	
	http.Redirect(w, r, ssoUrl, http.StatusSeeOther)
}
