package api

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/SigNoz/signoz/pkg/query-service/constants"
	"github.com/SigNoz/signoz/pkg/types"
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

	// Check if this is an incoming SAML Single Logout Request (SLO) from Keycloak
	samlRequest := r.FormValue("SAMLRequest")
	if samlRequest != "" {
		ah.handleSamlLogoutRequest(w, r, samlRequest)
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

	// Extract role dynamically from SAML assertion
	samlRole := "VIEWER"
	roleAttributes := []string{
		"role", "Role", "roles", "Roles",
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role",
	}
	for _, attrName := range roleAttributes {
		if attr, ok := assertionInfo.Values[attrName]; ok && len(attr.Values) > 0 {
			samlRole = attr.Values[0].Value
			break
		}
	}
	
	// Map Keycloak roles dynamically from environment variables (comma-separated lists)
	adminRoles := getCommaSeparatedEnv("SIGNOZ_SSO_ADMIN_ROLES", []string{"admin", "administrator"})
	editorRoles := getCommaSeparatedEnv("SIGNOZ_SSO_EDITOR_ROLES", []string{"editor", "developer", "data_scientist"})
	
	signozRole := "VIEWER"
	samlRoleLower := strings.ToLower(samlRole)
	
	if contains(adminRoles, samlRoleLower) {
		signozRole = "ADMIN"
	} else if contains(editorRoles, samlRoleLower) {
		signozRole = "EDITOR"
	} else {
		signozRole = "VIEWER"
	}

	nextPage, err := ah.Signoz.Modules.User.PrepareSsoRedirectWithRole(ctx, redirectUri, email, signozRole)
	if err != nil {
		zap.L().Error("[receiveSAML] failed to generate redirect URI after successful login ", zap.String("domain", domain.String()), zap.Error(err))
		handleSsoError(w, r, redirectUri)
		return
	}

	http.Redirect(w, r, nextPage, http.StatusSeeOther)
}

func (ah *APIHandler) autoRedirectSAML(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Get site URL first, fallback to SIGNOZ_SAML_RETURN_URL if SIGNOZ_SITE_URL is not set
	siteURLStr := os.Getenv("SIGNOZ_SITE_URL")
	if siteURLStr == "" || siteURLStr == "0.0.0.0:8080" {
		samlReturnURL := os.Getenv("SIGNOZ_SAML_RETURN_URL")
		if samlReturnURL != "" {
			siteURLStr = strings.Split(samlReturnURL, "/api/v1/complete/saml")[0]
		}
	}
	if siteURLStr == "" {
		siteURLStr = constants.GetDefaultSiteURL()
	}
	
	siteUrl, err := url.Parse(siteURLStr)
	if err != nil {
		zap.L().Error("[autoRedirectSAML] failed to parse site URL", zap.Error(err))
		http.Redirect(w, r, "/log-aggregator/login?password=Y", http.StatusSeeOther)
		return
	}
	
	// Ensure the path ends with /login for fallback
	fallbackPath := siteUrl.Scheme + "://" + siteUrl.Host + siteUrl.Path
	if !strings.HasSuffix(fallbackPath, "/login") {
		fallbackPath = strings.TrimSuffix(fallbackPath, "/") + "/login"
	}
	
	// Query the first SSO-enabled domain
	var stored []types.StorableOrgDomain
	err = ah.Signoz.SQLStore.BunDB().NewSelect().
		Model(&stored).
		Limit(1).
		Scan(ctx)
		
	if err != nil || len(stored) == 0 {
		zap.L().Error("[autoRedirectSAML] failed to list domains or no domain found", zap.Error(err))
		http.Redirect(w, r, fallbackPath+"?password=Y", http.StatusSeeOther)
		return
	}
	
	gettableDomain := &types.GettableOrgDomain{StorableOrgDomain: stored[0]}
	if err := gettableDomain.LoadConfig(stored[0].Data); err != nil || !gettableDomain.SsoEnabled {
		zap.L().Error("[autoRedirectSAML] domain SSO not enabled or failed to load config")
		http.Redirect(w, r, fallbackPath+"?password=Y", http.StatusSeeOther)
		return
	}
	
	// Ensure the path ends with /login for the React app to handle the JWT callback
	if !strings.HasSuffix(siteUrl.Path, "/login") {
		siteUrl.Path = strings.TrimSuffix(siteUrl.Path, "/") + "/login"
	}
	
	ssoUrl, err := gettableDomain.BuildSsoUrl(siteUrl)
	if err != nil {
		zap.L().Error("[autoRedirectSAML] failed to build SSO URL", zap.Error(err))
		http.Redirect(w, r, fallbackPath+"?password=Y", http.StatusSeeOther)
		return
	}
	
	http.Redirect(w, r, ssoUrl, http.StatusSeeOther)
}

func (ah *APIHandler) ssoLogout(w http.ResponseWriter, r *http.Request) {
	issuerURL := os.Getenv("SIGNOZ_OIDC_ISSUER_URL")
	clientID := os.Getenv("SIGNOZ_OIDC_CLIENT_ID")
	
	// Determine the post-logout redirect URI dynamically using SAML Return URL or Site URL
	siteURLStr := os.Getenv("SIGNOZ_SITE_URL")
	if siteURLStr == "" || siteURLStr == "0.0.0.0:8080" {
		samlReturnURL := os.Getenv("SIGNOZ_SAML_RETURN_URL")
		if samlReturnURL != "" {
			siteURLStr = strings.Split(samlReturnURL, "/api/v1/complete/saml")[0]
		}
	}
	if siteURLStr == "" {
		siteURLStr = constants.GetDefaultSiteURL()
	}
	
	redirectURI := "/login"
	if parsedSiteURL, err := url.Parse(siteURLStr); err == nil {
		if !strings.HasSuffix(parsedSiteURL.Path, "/login") {
			parsedSiteURL.Path = strings.TrimSuffix(parsedSiteURL.Path, "/") + "/login"
		}
		redirectURI = parsedSiteURL.String()
	}

	if issuerURL == "" || clientID == "" {
		// Fallback to normal login page if not configured
		http.Redirect(w, r, redirectURI, http.StatusSeeOther)
		return
	}
	
	// Build the OIDC single logout URL for Keycloak
	logoutURL := fmt.Sprintf("%s/protocol/openid-connect/logout?post_logout_redirect_uri=%s&client_id=%s",
		strings.TrimSuffix(issuerURL, "/"),
		url.QueryEscape(redirectURI),
		url.QueryEscape(clientID),
	)
	
	http.Redirect(w, r, logoutURL, http.StatusSeeOther)
}

func (ah *APIHandler) handleSamlLogoutRequest(w http.ResponseWriter, r *http.Request, samlRequest string) {
	issuerURL := os.Getenv("SIGNOZ_OIDC_ISSUER_URL")
	if issuerURL == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	
	samlIdpURL := strings.TrimSuffix(issuerURL, "/")
	if !strings.HasSuffix(samlIdpURL, "/protocol/saml") {
		samlIdpURL = strings.Replace(samlIdpURL, "/protocol/openid-connect", "/protocol/saml", 1)
		if !strings.Contains(samlIdpURL, "/protocol/saml") {
			samlIdpURL = samlIdpURL + "/protocol/saml"
		}
	}
	
	requestID := getSAMLRequestID(samlRequest)
	
	clientID := os.Getenv("SIGNOZ_OIDC_CLIENT_ID")
	if clientID == "" {
		clientID = "signoz"
	}
	
	logoutResponseXML := buildLogoutResponse(requestID, samlIdpURL, clientID)
	encodedResponse := encodeSAMLResponse(logoutResponseXML)
	
	relayState := r.FormValue("RelayState")
	
	keycloakRedirectURL := fmt.Sprintf("%s?SAMLResponse=%s", samlIdpURL, url.QueryEscape(encodedResponse))
	if relayState != "" {
		keycloakRedirectURL = fmt.Sprintf("%s&RelayState=%s", keycloakRedirectURL, url.QueryEscape(relayState))
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<script>
  (function() {
    localStorage.removeItem("AUTH_TOKEN");
    localStorage.removeItem("IS_LOGGED_IN");
    localStorage.removeItem("IS_IDENTIFIED_USER");
    localStorage.removeItem("REFRESH_AUTH_TOKEN");
    localStorage.removeItem("LOGGED_IN_USER_EMAIL");
    localStorage.removeItem("LOGGED_IN_USER_NAME");
    
    window.location.href = %q;
  })();
</script>
</head>
<body>
  <p>Logging out...</p>
</body>
</html>`, keycloakRedirectURL)

	w.Write([]byte(html))
}

func getSAMLRequestID(samlRequest string) string {
	data, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		return ""
	}
	
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	decompressed, err := io.ReadAll(r)
	if err != nil {
		decompressed = data
	}
	
	re := regexp.MustCompile(`ID="([^"]+)"`)
	matches := re.FindSubmatch(decompressed)
	if len(matches) > 1 {
		return string(matches[1])
	}
	
	reSingle := regexp.MustCompile(`ID='([^']+)'`)
	matchesSingle := reSingle.FindSubmatch(decompressed)
	if len(matchesSingle) > 1 {
		return string(matchesSingle[1])
	}
	
	return ""
}

func buildLogoutResponse(inResponseTo, destination, issuer string) string {
	id := "_" + uuid.New().String()
	instant := time.Now().UTC().Format(time.RFC3339)
	return fmt.Sprintf(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s"><saml:Issuer>%s</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>`,
		id, instant, destination, inResponseTo, issuer)
}

func encodeSAMLResponse(xml string) string {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write([]byte(xml))
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func getCommaSeparatedEnv(key string, defaults []string) []string {
	val := os.Getenv(key)
	if val == "" {
		return defaults
	}
	parts := strings.Split(val, ",")
	var result []string
	for _, p := range parts {
		trimmed := strings.ToLower(strings.TrimSpace(p))
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func contains(arr []string, val string) bool {
	for _, item := range arr {
		if item == val {
			return true
		}
	}
	return false
}


