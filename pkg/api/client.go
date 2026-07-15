package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to netpolicyd over HTTP or a Unix socket.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// ClientOption configures the client.
type ClientOption func(*Client)

// WithToken sets the bearer token.
func WithToken(token string) ClientOption {
	return func(c *Client) { c.token = token }
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = hc }
}

// WithUnixSocket dials a Unix domain socket. baseURL should be like "http://localhost".
func WithUnixSocket(socketPath string) ClientOption {
	return func(c *Client) {
		c.httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		}
		if c.baseURL == "" {
			c.baseURL = "http://localhost"
		}
	}
}

// NewClient creates an API client.
// urlOrUnix may be "http://host:port", "https://...", or "unix:///path/to.sock".
func NewClient(urlOrUnix string, opts ...ClientOption) (*Client, error) {
	c := &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	if strings.HasPrefix(urlOrUnix, "unix://") {
		path := strings.TrimPrefix(urlOrUnix, "unix://")
		c.baseURL = "http://localhost"
		WithUnixSocket(path)(c)
	} else {
		c.baseURL = strings.TrimRight(urlOrUnix, "/")
	}
	for _, o := range opts {
		o(c)
	}
	if c.baseURL == "" {
		return nil, fmt.Errorf("empty base URL")
	}
	return c, nil
}

// BaseURL returns the configured endpoint.
func (c *Client) BaseURL() string { return c.baseURL }

func (c *Client) do(ctx context.Context, method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var eb ErrorBody
		if json.Unmarshal(data, &eb) == nil && eb.Error.Message != "" {
			return &APIError{Status: resp.StatusCode, Code: eb.Error.Code, Message: eb.Error.Message}
		}
		return &APIError{Status: resp.StatusCode, Message: string(data)}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// Health checks /healthz.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/healthz", nil, nil)
}

// Version returns version info.
func (c *Client) Version(ctx context.Context) (*VersionInfo, error) {
	var v VersionInfo
	if err := c.do(ctx, http.MethodGet, "/v1/version", nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// Status returns /v1/status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var st Status
	if err := c.do(ctx, http.MethodGet, "/v1/status", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Overview returns status + policies + routes + NAT + forwards (+ optional dataplane).
func (c *Client) Overview(ctx context.Context, skipHost bool) (*Overview, error) {
	path := "/v1/overview"
	if skipHost {
		path += "?skip_host=1"
	}
	var ov Overview
	if err := c.do(ctx, http.MethodGet, path, nil, &ov); err != nil {
		return nil, err
	}
	return &ov, nil
}

// Dataplane returns live host dump.
func (c *Client) Dataplane(ctx context.Context) (*Dataplane, error) {
	var d Dataplane
	if err := c.do(ctx, http.MethodGet, "/v1/dataplane", nil, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Traffic returns live interface rates + socket inventory.
func (c *Client) Traffic(ctx context.Context) (*TrafficSnapshot, error) {
	var t TrafficSnapshot
	if err := c.do(ctx, http.MethodGet, "/v1/traffic", nil, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// ListPolicies lists policy rules.
func (c *Client) ListPolicies(ctx context.Context) ([]PolicyRule, error) {
	var out []PolicyRule
	if err := c.do(ctx, http.MethodGet, "/v1/policies", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreatePolicy creates a policy rule.
func (c *Client) CreatePolicy(ctx context.Context, req PolicyCreateRequest) (*PolicyRule, error) {
	var out PolicyRule
	if err := c.do(ctx, http.MethodPost, "/v1/policies", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdatePolicy patches a policy rule.
func (c *Client) UpdatePolicy(ctx context.Context, id string, req PolicyUpdateRequest) (*PolicyRule, error) {
	var out PolicyRule
	if err := c.do(ctx, http.MethodPatch, "/v1/policies/"+url.PathEscape(id), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeletePolicy removes a policy rule.
func (c *Client) DeletePolicy(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/policies/"+url.PathEscape(id), nil, nil)
}

// ListRoutes lists explicit routes.
func (c *Client) ListRoutes(ctx context.Context) ([]RouteSpec, error) {
	var out []RouteSpec
	if err := c.do(ctx, http.MethodGet, "/v1/routes", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateRoute upserts a route.
func (c *Client) CreateRoute(ctx context.Context, rt RouteSpec) (*RouteSpec, error) {
	var out RouteSpec
	if err := c.do(ctx, http.MethodPost, "/v1/routes", rt, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteRoute removes a route by id.
func (c *Client) DeleteRoute(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/routes/"+url.PathEscape(id), nil, nil)
}

// ListNAT lists NAT rules.
func (c *Client) ListNAT(ctx context.Context) ([]NATSpec, error) {
	var out []NATSpec
	if err := c.do(ctx, http.MethodGet, "/v1/nat", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateNAT upserts a NAT rule.
func (c *Client) CreateNAT(ctx context.Context, n NATSpec) (*NATSpec, error) {
	var out NATSpec
	if err := c.do(ctx, http.MethodPost, "/v1/nat", n, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteNAT removes a NAT rule by id.
func (c *Client) DeleteNAT(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/nat/"+url.PathEscape(id), nil, nil)
}

// ListForwards lists forward rules.
func (c *Client) ListForwards(ctx context.Context) ([]ForwardSpec, error) {
	var out []ForwardSpec
	if err := c.do(ctx, http.MethodGet, "/v1/forwards", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateForward upserts a forward rule.
func (c *Client) CreateForward(ctx context.Context, f ForwardSpec) (*ForwardSpec, error) {
	var out ForwardSpec
	if err := c.do(ctx, http.MethodPost, "/v1/forwards", f, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteForward removes a forward rule by id.
func (c *Client) DeleteForward(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/forwards/"+url.PathEscape(id), nil, nil)
}

// ListTC lists traffic-control limits.
func (c *Client) ListTC(ctx context.Context) ([]TCSpec, error) {
	var out []TCSpec
	if err := c.do(ctx, http.MethodGet, "/v1/tc", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateTC upserts a TC limit.
func (c *Client) CreateTC(ctx context.Context, t TCSpec) (*TCSpec, error) {
	var out TCSpec
	if err := c.do(ctx, http.MethodPost, "/v1/tc", t, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteTC removes a TC limit by id.
func (c *Client) DeleteTC(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/tc/"+url.PathEscape(id), nil, nil)
}

// ListFirewall lists firewall rules.
func (c *Client) ListFirewall(ctx context.Context) ([]FirewallRule, error) {
	var out []FirewallRule
	if err := c.do(ctx, http.MethodGet, "/v1/firewall", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateFirewall upserts a firewall rule.
func (c *Client) CreateFirewall(ctx context.Context, r FirewallRule) (*FirewallRule, error) {
	var out FirewallRule
	if err := c.do(ctx, http.MethodPost, "/v1/firewall", r, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteFirewall removes a firewall rule.
func (c *Client) DeleteFirewall(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/firewall/"+url.PathEscape(id), nil, nil)
}

// ListIPAddrs lists managed addresses.
func (c *Client) ListIPAddrs(ctx context.Context) ([]IPAddrSpec, error) {
	var out []IPAddrSpec
	if err := c.do(ctx, http.MethodGet, "/v1/ip/addrs", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateIPAddr upserts an address.
func (c *Client) CreateIPAddr(ctx context.Context, a IPAddrSpec) (*IPAddrSpec, error) {
	var out IPAddrSpec
	if err := c.do(ctx, http.MethodPost, "/v1/ip/addrs", a, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteIPAddr removes a managed address.
func (c *Client) DeleteIPAddr(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/ip/addrs/"+url.PathEscape(id), nil, nil)
}

// ListIPRules lists managed ip rules.
func (c *Client) ListIPRules(ctx context.Context) ([]IPRuleSpec, error) {
	var out []IPRuleSpec
	if err := c.do(ctx, http.MethodGet, "/v1/ip/rules", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateIPRule upserts an ip rule.
func (c *Client) CreateIPRule(ctx context.Context, r IPRuleSpec) (*IPRuleSpec, error) {
	var out IPRuleSpec
	if err := c.do(ctx, http.MethodPost, "/v1/ip/rules", r, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteIPRule removes an ip rule.
func (c *Client) DeleteIPRule(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/ip/rules/"+url.PathEscape(id), nil, nil)
}

// ListLinks lists managed links.
func (c *Client) ListLinks(ctx context.Context) ([]LinkSpec, error) {
	var out []LinkSpec
	if err := c.do(ctx, http.MethodGet, "/v1/ip/links", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateLink upserts a link config.
func (c *Client) CreateLink(ctx context.Context, l LinkSpec) (*LinkSpec, error) {
	var out LinkSpec
	if err := c.do(ctx, http.MethodPost, "/v1/ip/links", l, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteLink removes a managed link config.
func (c *Client) DeleteLink(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/ip/links/"+url.PathEscape(id), nil, nil)
}

// Apply runs reconcile (optionally dry-run).
func (c *Client) Apply(ctx context.Context, dryRun bool) (*ApplyResult, error) {
	path := "/v1/apply"
	if dryRun {
		path += "?dry_run=1"
	}
	var out ApplyResult
	if err := c.do(ctx, http.MethodPost, path, map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetIPForward sets net.ipv4.ip_forward managed flag.
func (c *Client) SetIPForward(ctx context.Context, enabled bool) error {
	return c.do(ctx, http.MethodPut, "/v1/sysctl/ip_forward", map[string]bool{"enabled": enabled}, nil)
}

// ListSysctls lists managed sysctls.
func (c *Client) ListSysctls(ctx context.Context) ([]SysctlSpec, error) {
	var out []SysctlSpec
	if err := c.do(ctx, http.MethodGet, "/v1/sysctl", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UpsertSysctl sets a managed sysctl (applied on reconcile).
func (c *Client) UpsertSysctl(ctx context.Context, s SysctlSpec) (*SysctlSpec, error) {
	var out SysctlSpec
	if err := c.do(ctx, http.MethodPost, "/v1/sysctl", s, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteSysctl removes a managed sysctl by key.
func (c *Client) DeleteSysctl(ctx context.Context, key string) error {
	return c.do(ctx, http.MethodDelete, "/v1/sysctl/"+url.PathEscape(key), nil, nil)
}

// ListIPLists lists named IP/CIDR lists.
func (c *Client) ListIPLists(ctx context.Context) ([]IPList, error) {
	var out []IPList
	if err := c.do(ctx, http.MethodGet, "/v1/ip/lists", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateIPList creates or replaces a list.
func (c *Client) CreateIPList(ctx context.Context, l IPList) (*IPList, error) {
	var out IPList
	if err := c.do(ctx, http.MethodPost, "/v1/ip/lists", l, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AppendIPListEntries adds IPs/CIDRs to a list.
func (c *Client) AppendIPListEntries(ctx context.Context, idOrName string, entries []string) (*IPList, error) {
	var out IPList
	body := map[string]any{"entries": entries}
	if err := c.do(ctx, http.MethodPost, "/v1/ip/lists/"+url.PathEscape(idOrName)+"/entries", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteIPList removes a list.
func (c *Client) DeleteIPList(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/ip/lists/"+url.PathEscape(id), nil, nil)
}

// PutDesired replaces desired state and applies.
func (c *Client) PutDesired(ctx context.Context, d DesiredState) (*ApplyResult, error) {
	var out ApplyResult
	if err := c.do(ctx, http.MethodPut, "/v1/desired", d, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
