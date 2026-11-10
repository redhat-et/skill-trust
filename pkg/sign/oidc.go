package sign

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// GitHub OIDC runtime environment variables, present in jobs that declare
// the id-token: write permission.
const (
	envRequestURL   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	envRequestToken = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

// ErrOIDCUnavailable indicates a GitHub Actions OIDC token could not be
// fetched: the runtime variables are absent (no id-token: write
// permission) or the request failed.
var ErrOIDCUnavailable = fmt.Errorf("github oidc token unavailable")

// GitHubOIDCAudience is the token audience Sigstore Fulcio deployments
// expect by convention.
const GitHubOIDCAudience = "sigstore"

// GitHubOIDCToken fetches an OIDC identity token from the GitHub Actions
// runtime, requesting the given audience (conventionally "sigstore").
//
// GitHub provides ACTIONS_ID_TOKEN_REQUEST_URL and
// ACTIONS_ID_TOKEN_REQUEST_TOKEN to jobs with the id-token: write
// permission. The token's subject becomes the Fulcio certificate SAN
// (https://github.com/<owner>/<repo>/<workflow-path>@<ref>) and its
// issuer and claims are recorded as certificate extensions, which
// verification policy constrains through certificate identity and
// provenance rules.
func GitHubOIDCToken(ctx context.Context, audience string) (string, error) {
	requestURL := os.Getenv(envRequestURL)
	requestToken := os.Getenv(envRequestToken)
	if requestURL == "" || requestToken == "" {
		return "", fmt.Errorf("%w: %s and %s are not set; the job needs the id-token: write permission",
			ErrOIDCUnavailable, envRequestURL, envRequestToken)
	}

	u, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("%w: invalid %s: %v", ErrOIDCUnavailable, envRequestURL, err)
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOIDCUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOIDCUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("%w: reading response: %v", ErrOIDCUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: token endpoint returned %s: %s",
			ErrOIDCUnavailable, resp.Status, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("%w: parsing response: %v", ErrOIDCUnavailable, err)
	}
	if payload.Value == "" {
		return "", fmt.Errorf("%w: response carries no token", ErrOIDCUnavailable)
	}
	return payload.Value, nil
}
