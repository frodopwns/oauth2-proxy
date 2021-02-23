package options

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/spf13/pflag"
)

type LegacyOptions struct {
	// Legacy options related to upstream servers
	LegacyUpstreams LegacyUpstreams `cfg:",squash"`

	// Legacy options for injecting request/response headers
	LegacyHeaders LegacyHeaders `cfg:",squash"`

	Options Options `cfg:",squash"`
}

func NewLegacyOptions() *LegacyOptions {
	return &LegacyOptions{
		LegacyUpstreams: LegacyUpstreams{
			PassHostHeader:  true,
			ProxyWebSockets: true,
			FlushInterval:   DefaultUpstreamFlushInterval,
		},

		LegacyHeaders: LegacyHeaders{
			PassBasicAuth:        true,
			PassUserHeaders:      true,
			SkipAuthStripHeaders: true,
		},

		Options: *NewOptions(),
	}
}

func NewLegacyFlagSet() *pflag.FlagSet {
	flagSet := NewFlagSet()

	flagSet.AddFlagSet(legacyUpstreamsFlagSet())
	flagSet.AddFlagSet(legacyHeadersFlagSet())

	return flagSet
}

func (l *LegacyOptions) ToOptions() (*Options, error) {
	upstreams, err := l.LegacyUpstreams.convert()
	if err != nil {
		return nil, fmt.Errorf("error converting upstreams: %v", err)
	}
	l.Options.UpstreamServers = upstreams

	l.Options.InjectRequestHeaders, l.Options.InjectResponseHeaders = l.LegacyHeaders.convert()
	return &l.Options, nil
}

type LegacyUpstreams struct {
	FlushInterval                 time.Duration `flag:"flush-interval" cfg:"flush_interval"`
	PassHostHeader                bool          `flag:"pass-host-header" cfg:"pass_host_header"`
	ProxyWebSockets               bool          `flag:"proxy-websockets" cfg:"proxy_websockets"`
	SSLUpstreamInsecureSkipVerify bool          `flag:"ssl-upstream-insecure-skip-verify" cfg:"ssl_upstream_insecure_skip_verify"`
	Upstreams                     []string      `flag:"upstream" cfg:"upstreams"`
}

func legacyUpstreamsFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("upstreams", pflag.ExitOnError)

	flagSet.Duration("flush-interval", DefaultUpstreamFlushInterval, "period between response flushing when streaming responses")
	flagSet.Bool("pass-host-header", true, "pass the request Host Header to upstream")
	flagSet.Bool("proxy-websockets", true, "enables WebSocket proxying")
	flagSet.Bool("ssl-upstream-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS upstreams")
	flagSet.StringSlice("upstream", []string{}, "the http url(s) of the upstream endpoint, file:// paths for static files or static://<status_code> for static response. Routing is based on the path")

	return flagSet
}

func (l *LegacyUpstreams) convert() (Upstreams, error) {
	upstreams := Upstreams{}

	for _, upstreamString := range l.Upstreams {
		u, err := url.Parse(upstreamString)
		if err != nil {
			return nil, fmt.Errorf("could not parse upstream %q: %v", upstreamString, err)
		}

		if u.Path == "" {
			u.Path = "/"
		}

		flushInterval := Duration(l.FlushInterval)
		upstream := Upstream{
			ID:                    u.Path,
			Path:                  u.Path,
			URI:                   upstreamString,
			InsecureSkipTLSVerify: l.SSLUpstreamInsecureSkipVerify,
			PassHostHeader:        &l.PassHostHeader,
			ProxyWebSockets:       &l.ProxyWebSockets,
			FlushInterval:         &flushInterval,
		}

		switch u.Scheme {
		case "file":
			if u.Fragment != "" {
				upstream.ID = u.Fragment
				upstream.Path = u.Fragment
				// Trim the fragment from the end of the URI
				upstream.URI = strings.SplitN(upstreamString, "#", 2)[0]
			}
		case "static":
			responseCode, err := strconv.Atoi(u.Host)
			if err != nil {
				logger.Errorf("unable to convert %q to int, use default \"200\"", u.Host)
				responseCode = 200
			}
			upstream.Static = true
			upstream.StaticCode = &responseCode

			// This is not allowed to be empty and must be unique
			upstream.ID = upstreamString

			// We only support the root path in the legacy config
			upstream.Path = "/"

			// Force defaults compatible with static responses
			upstream.URI = ""
			upstream.InsecureSkipTLSVerify = false
			upstream.PassHostHeader = nil
			upstream.ProxyWebSockets = nil
			upstream.FlushInterval = nil
		}

		upstreams = append(upstreams, upstream)
	}

	return upstreams, nil
}

type LegacyHeaders struct {
	PassBasicAuth     bool `flag:"pass-basic-auth" cfg:"pass_basic_auth"`
	PassAccessToken   bool `flag:"pass-access-token" cfg:"pass_access_token"`
	PassUserHeaders   bool `flag:"pass-user-headers" cfg:"pass_user_headers"`
	PassAuthorization bool `flag:"pass-authorization-header" cfg:"pass_authorization_header"`

	SetBasicAuth     bool `flag:"set-basic-auth" cfg:"set_basic_auth"`
	SetXAuthRequest  bool `flag:"set-xauthrequest" cfg:"set_xauthrequest"`
	SetAuthorization bool `flag:"set-authorization-header" cfg:"set_authorization_header"`

	PreferEmailToUser    bool   `flag:"prefer-email-to-user" cfg:"prefer_email_to_user"`
	BasicAuthPassword    string `flag:"basic-auth-password" cfg:"basic_auth_password"`
	SkipAuthStripHeaders bool   `flag:"skip-auth-strip-headers" cfg:"skip_auth_strip_headers"`

	// vmware additions
	ExtraHeaders []string `flag:"extra-headers" cfg:"extra_headers"`
	GazIdpID     string   `flag:"gaz-idp-id" cfg:"gaz_idp_id"`
	GazContextID string   `flag:"gaz-context-id" cfg:"gaz_context_id"`
}

func legacyHeadersFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("headers", pflag.ExitOnError)

	flagSet.Bool("pass-basic-auth", true, "pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.Bool("pass-access-token", false, "pass OAuth access_token to upstream via X-Forwarded-Access-Token header")
	flagSet.Bool("pass-user-headers", true, "pass X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.Bool("pass-authorization-header", false, "pass the Authorization Header to upstream")

	flagSet.Bool("set-basic-auth", false, "set HTTP Basic Auth information in response (useful in Nginx auth_request mode)")
	flagSet.Bool("set-xauthrequest", false, "set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)")
	flagSet.Bool("set-authorization-header", false, "set Authorization response headers (useful in Nginx auth_request mode)")

	flagSet.Bool("prefer-email-to-user", false, "Prefer to use the Email address as the Username when passing information to upstream. Will only use Username if Email is unavailable, eg. htaccess authentication. Used in conjunction with -pass-basic-auth and -pass-user-headers")
	flagSet.String("basic-auth-password", "", "the password to set when passing the HTTP Basic Auth header")
	flagSet.Bool("skip-auth-strip-headers", true, "strips X-Forwarded-* style authentication headers & Authorization header if they would be set by oauth2-proxy")

	// vmware additions
	flagSet.String("gaz-idp-id", "", "Value for the idp_id parameter")
	flagSet.String("gaz-context-id", "", "Value for the context_id parameter")
	flagSet.StringSlice("extra-headers", []string{}, "extra headers to pass to the upstream 'Header: Value' format")

	return flagSet
}

// convert takes the legacy request/response headers and converts them to
// the new format for InjectRequestHeaders and InjectResponseHeaders
func (l *LegacyHeaders) convert() ([]Header, []Header) {
	return l.getRequestHeaders(), l.getResponseHeaders()
}

func (l *LegacyHeaders) getRequestHeaders() []Header {
	requestHeaders := []Header{}

	if l.PassBasicAuth && l.BasicAuthPassword != "" {
		requestHeaders = append(requestHeaders, getBasicAuthHeader(l.PreferEmailToUser, l.BasicAuthPassword))
	}

	// In the old implementation, PassUserHeaders is a subset of PassBasicAuth
	if l.PassBasicAuth || l.PassUserHeaders {
		requestHeaders = append(requestHeaders, getPassUserHeaders(l.PreferEmailToUser)...)
		requestHeaders = append(requestHeaders, getPreferredUsernameHeader())
	}

	if l.PassAccessToken {
		requestHeaders = append(requestHeaders, getPassAccessTokenHeader())
	}

	if l.PassAuthorization {
		requestHeaders = append(requestHeaders, getAuthorizationHeader())
	}

	// vmware addition
	for _, hv := range l.ExtraHeaders {
		parts := strings.Split(hv, ":")
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		requestHeaders = append(requestHeaders, Header{
			Name: name,
			Values: []HeaderValue{
				{
					StringSource: &StringSource{
						Value: value,
					},
				},
			},
		})
	}

	for i := range requestHeaders {
		requestHeaders[i].PreserveRequestValue = !l.SkipAuthStripHeaders
	}

	return requestHeaders
}

func (l *LegacyHeaders) getResponseHeaders() []Header {
	responseHeaders := []Header{}

	if l.SetXAuthRequest {
		responseHeaders = append(responseHeaders, getXAuthRequestHeaders()...)
		if l.PassAccessToken {
			responseHeaders = append(responseHeaders, getXAuthRequestAccessTokenHeader())
		}
	}

	if l.SetBasicAuth {
		responseHeaders = append(responseHeaders, getBasicAuthHeader(l.PreferEmailToUser, l.BasicAuthPassword))
	}

	if l.SetAuthorization {
		responseHeaders = append(responseHeaders, getAuthorizationHeader())
	}

	return responseHeaders
}

func getBasicAuthHeader(preferEmailToUser bool, basicAuthPassword string) Header {
	claim := "user"
	if preferEmailToUser {
		claim = "email"
	}

	return Header{
		Name: "Authorization",
		Values: []HeaderValue{
			{
				ClaimSource: &ClaimSource{
					Claim:  claim,
					Prefix: "Basic ",
					BasicAuthPassword: &SecretSource{
						Value: []byte(basicAuthPassword),
					},
				},
			},
		},
	}
}

func getPassUserHeaders(preferEmailToUser bool) []Header {
	headers := []Header{
		{
			Name: "X-Forwarded-Groups",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "groups",
					},
				},
			},
		},
	}

	if preferEmailToUser {
		return append(headers,
			Header{
				Name: "X-Forwarded-User",
				Values: []HeaderValue{
					{
						ClaimSource: &ClaimSource{
							Claim: "email",
						},
					},
				},
			},
		)
	}

	return append(headers,
		Header{
			Name: "X-Forwarded-User",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "user",
					},
				},
			},
		},
		Header{
			Name: "X-Forwarded-Email",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "email",
					},
				},
			},
		},
	)
}

func getPassAccessTokenHeader() Header {
	return Header{
		Name: "X-Forwarded-Access-Token",
		Values: []HeaderValue{
			{
				ClaimSource: &ClaimSource{
					Claim: "access_token",
				},
			},
		},
	}
}

func getAuthorizationHeader() Header {
	return Header{
		Name: "Authorization",
		Values: []HeaderValue{
			{
				ClaimSource: &ClaimSource{
					Claim:  "id_token",
					Prefix: "Bearer ",
				},
			},
		},
	}
}

func getPreferredUsernameHeader() Header {
	return Header{
		Name: "X-Forwarded-Preferred-Username",
		Values: []HeaderValue{
			{
				ClaimSource: &ClaimSource{
					Claim: "preferred_username",
				},
			},
		},
	}
}

func getXAuthRequestHeaders() []Header {
	headers := []Header{
		{
			Name: "X-Auth-Request-User",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "user",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Email",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "email",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Preferred-Username",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "preferred_username",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Groups",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "groups",
					},
				},
			},
		},
	}

	return headers
}

func getXAuthRequestAccessTokenHeader() Header {
	return Header{
		Name: "X-Auth-Request-Access-Token",
		Values: []HeaderValue{
			{
				ClaimSource: &ClaimSource{
					Claim: "access_token",
				},
			},
		},
	}
}
