package providers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/bitly/oauth2_proxy/api"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
)

type CspProvider struct {
	*ProviderData
}

var _ Provider = (*CspProvider)(nil)

func NewCSPProvider(p *ProviderData) *CspProvider {
	p.ProviderName = "csp"

	return &CspProvider{ProviderData: p}
}

func (p *CspProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	//params.Add("client_id", p.ClientID)
	//params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	auth := fmt.Sprintf("%s:%s", p.ClientID, p.ClientSecret)
	auth = base64.StdEncoding.EncodeToString([]byte(auth))
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)

	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		s = &sessions.SessionState{
			AccessToken: jsonResponse.AccessToken,
		}
		return
	}

	var v url.Values
	v, err = url.ParseQuery(string(body))
	if err != nil {
		return
	}
	if a := v.Get("access_token"); a != "" {
		s = &sessions.SessionState{AccessToken: a}
	} else {
		err = fmt.Errorf("no access token found %s", body)
	}
	return
}

// GetLoginURL with typical oauth parameters
func (p *CspProvider) GetLoginURL(redirectURI, state string) string {
	var a url.URL
	a = *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Set("approval_prompt", p.ApprovalPrompt)
	//	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	a.RawQuery = params.Encode()
	return a.String()
}

// CookieForSession serializes a session state for storage in a cookie
func (p *CspProvider) CookieForSession(s *sessions.SessionState, c *encryption.Cipher) (string, error) {
	bytes, err := s.EncodeSessionState(c)
	return string(bytes), err
}

// SessionFromCookie deserializes a session from a cookie value
func (p *CspProvider) SessionFromCookie(v string, c *encryption.Cipher) (s *sessions.SessionState, err error) {
	return sessions.DecodeSessionState(v, c)
}

func (p *CspProvider) GetEmailAddress(ctx context.Context, *sessions.SessionState) (string, error) {
	req, err := http.NewRequest("GET", p.ValidateURL.String(), nil)
	req.Header.Set("csp-auth-token", s.AccessToken)

	if err != nil {
		log.Printf("failed building request %s", err)
		return "", err
	}
	json, err := api.Request(req)
	if err != nil {
		log.Printf("failed making request %s", err)
		return "", err
	}

	username, err := json.Get("username").String()
	if err != nil {
		return "", err
	}

	if strings.Contains(username, "@") {
		return username, nil
	}

	domain, err := json.Get("domain").String()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s@%s", username, domain), nil
}

// GetUserName returns the Account username
func (p *CspProvider) GetUserName(s *sessions.SessionState) (string, error) {
	return p.GetEmailAddress(s)
}

// ValidateGroup validates that the provided email exists in the configured provider
// email group(s).
func (p *CspProvider) ValidateGroup(email string) bool {
	return true
}

func (p *CspProvider) ValidateSessionState(s *sessions.SessionState) bool {
	_, err := p.GetEmailAddress(s)
	return err != nil
}

// RefreshSessionIfNeeded
func (p *CspProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	return false, nil
}
