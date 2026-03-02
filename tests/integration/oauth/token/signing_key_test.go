/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package token

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/asgardeo/thunder/tests/integration/testutils"
	"github.com/stretchr/testify/suite"
)

const (
	// skDefaultKeyID matches the key ID configured under crypto.keys in the server's deployment.yaml.
	skDefaultKeyID = "default-key"

	// Unique client IDs for this suite to avoid conflicts with other test suites.
	skNoKeyClientID     = "sk_nokey_client"
	skNoKeyClientSecret = "sk_nokey_secret"

	skDefaultKeyClientID     = "sk_defkey_client"
	skDefaultKeyClientSecret = "sk_defkey_secret"
)

// SigningKeyTokenSuite tests that the JWT access-token header reflects the per-application
// signing key configuration.
type SigningKeyTokenSuite struct {
	suite.Suite

	// appIDNoKey is an OAuth app created without a signing_key_id (uses global default).
	appIDNoKey string
	// appIDDefaultKey is an OAuth app created with signing_key_id="default-key".
	appIDDefaultKey string

	client *http.Client
}

func TestSigningKeyTokenSuite(t *testing.T) {
	suite.Run(t, new(SigningKeyTokenSuite))
}

func (ts *SigningKeyTokenSuite) SetupSuite() {
	ts.client = testutils.GetHTTPClient()

	// App 1: no explicit signing_key_id — falls back to the global jwt.preferred_key_id.
	ts.appIDNoKey = ts.createApp(skNoKeyClientID, skNoKeyClientSecret, "")

	// App 2: signing_key_id explicitly set to "default-key" (same physical key as the global
	// preferred key, but exercising the per-app code path).
	ts.appIDDefaultKey = ts.createApp(skDefaultKeyClientID, skDefaultKeyClientSecret, skDefaultKeyID)
}

func (ts *SigningKeyTokenSuite) TearDownSuite() {
	ts.deleteApp(ts.appIDNoKey)
	ts.deleteApp(ts.appIDDefaultKey)
}

// TestAccessTokenKIDPresentForDefaultPath verifies that access tokens issued by an app
// without a signing_key_id contain a non-empty "kid" in the JWT header.
func (ts *SigningKeyTokenSuite) TestAccessTokenKIDPresentForDefaultPath() {
	tokenStr := ts.obtainClientCredentialsToken(skNoKeyClientID, skNoKeyClientSecret)

	header, err := testutils.DecodeJWTHeader(tokenStr)
	ts.Require().NoError(err, "failed to decode JWT header")
	ts.Assert().NotEmpty(header.KeyID,
		"JWT header 'kid' must be non-empty for the default signing path")
}

// TestAccessTokenKIDPresentForPerAppPath verifies that access tokens issued by an app
// with signing_key_id="default-key" contain a non-empty "kid" in the JWT header.
func (ts *SigningKeyTokenSuite) TestAccessTokenKIDPresentForPerAppPath() {
	tokenStr := ts.obtainClientCredentialsToken(skDefaultKeyClientID, skDefaultKeyClientSecret)

	header, err := testutils.DecodeJWTHeader(tokenStr)
	ts.Require().NoError(err, "failed to decode JWT header")
	ts.Assert().NotEmpty(header.KeyID,
		"JWT header 'kid' must be non-empty when signing_key_id is explicitly set")
}

// TestAccessTokenKIDMatchesBetweenDefaultAndPerAppPaths verifies that when the
// per-app signing_key_id refers to the same key as the global preferred key, both apps
// produce tokens with an identical "kid" header value.
func (ts *SigningKeyTokenSuite) TestAccessTokenKIDMatchesBetweenDefaultAndPerAppPaths() {
	defaultToken := ts.obtainClientCredentialsToken(skNoKeyClientID, skNoKeyClientSecret)
	perAppToken := ts.obtainClientCredentialsToken(skDefaultKeyClientID, skDefaultKeyClientSecret)

	defaultHeader, err := testutils.DecodeJWTHeader(defaultToken)
	ts.Require().NoError(err, "failed to decode JWT header from default-path token")

	perAppHeader, err := testutils.DecodeJWTHeader(perAppToken)
	ts.Require().NoError(err, "failed to decode JWT header from per-app-path token")

	ts.Assert().Equal(defaultHeader.KeyID, perAppHeader.KeyID,
		"kid should be identical when signing_key_id points to the same key as jwt.preferred_key_id")
}

// TestAccessTokenAlgorithmPresentForDefaultPath checks that the JWT header contains a
// non-empty "alg" field for the default signing path.
func (ts *SigningKeyTokenSuite) TestAccessTokenAlgorithmPresentForDefaultPath() {
	tokenStr := ts.obtainClientCredentialsToken(skNoKeyClientID, skNoKeyClientSecret)

	header, err := testutils.DecodeJWTHeader(tokenStr)
	ts.Require().NoError(err)
	ts.Assert().NotEmpty(header.Algorithm,
		"JWT header 'alg' must be present for the default signing path")
}

// TestAccessTokenAlgorithmPresentForPerAppPath checks that the JWT header contains a
// non-empty "alg" field when a per-app signing_key_id is configured.
func (ts *SigningKeyTokenSuite) TestAccessTokenAlgorithmPresentForPerAppPath() {
	tokenStr := ts.obtainClientCredentialsToken(skDefaultKeyClientID, skDefaultKeyClientSecret)

	header, err := testutils.DecodeJWTHeader(tokenStr)
	ts.Require().NoError(err)
	ts.Assert().NotEmpty(header.Algorithm,
		"JWT header 'alg' must be present when signing_key_id is explicitly set")
}

// TestAlgorithmMatchesBetweenDefaultAndPerAppPaths verifies that both paths produce
// tokens signed with the same algorithm (since they use the same underlying key).
func (ts *SigningKeyTokenSuite) TestAlgorithmMatchesBetweenDefaultAndPerAppPaths() {
	defaultToken := ts.obtainClientCredentialsToken(skNoKeyClientID, skNoKeyClientSecret)
	perAppToken := ts.obtainClientCredentialsToken(skDefaultKeyClientID, skDefaultKeyClientSecret)

	defaultHeader, err := testutils.DecodeJWTHeader(defaultToken)
	ts.Require().NoError(err)

	perAppHeader, err := testutils.DecodeJWTHeader(perAppToken)
	ts.Require().NoError(err)

	ts.Assert().Equal(defaultHeader.Algorithm, perAppHeader.Algorithm,
		"alg should be identical when the same key is used via different configuration paths")
}

// ── helpers ─────────────────────────────────────────────────────────────────

// createApp creates an OAuth2 application (client_credentials grant) and returns its ID.
// signingKeyID may be empty, which omits the field from the request.
func (ts *SigningKeyTokenSuite) createApp(clientID, clientSecret, signingKeyID string) string {
	oauthCfg := map[string]any{
		"client_id":                  clientID,
		"client_secret":              clientSecret,
		"redirect_uris":              []string{"https://localhost/callback"},
		"grant_types":                []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_basic",
	}
	if signingKeyID != "" {
		oauthCfg["signing_key_id"] = signingKeyID
	}

	appPayload := map[string]any{
		"name":                         fmt.Sprintf("SigningKeyTokenTest-%s", clientID),
		"description":                  "Integration test for JWT signing key on token endpoint",
		"is_registration_flow_enabled": false,
		"inbound_auth_config": []map[string]any{
			{
				"type":   "oauth2",
				"config": oauthCfg,
			},
		},
	}

	appJSON, err := json.Marshal(appPayload)
	ts.Require().NoError(err)

	req, err := http.NewRequest("POST", testServerURL+"/applications", bytes.NewReader(appJSON))
	ts.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.client.Do(req)
	ts.Require().NoError(err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	ts.Require().Equal(http.StatusCreated, resp.StatusCode,
		"failed to create test application (clientID=%s): %s", clientID, string(body))

	var created struct {
		ID string `json:"id"`
	}
	ts.Require().NoError(json.Unmarshal(body, &created))
	ts.Require().NotEmpty(created.ID)

	ts.T().Logf("Created test application %s with ID %s (signing_key_id=%q)",
		clientID, created.ID, signingKeyID)
	return created.ID
}

// deleteApp removes an application by ID; errors are logged but not fatal (teardown only).
func (ts *SigningKeyTokenSuite) deleteApp(appID string) {
	if appID == "" {
		return
	}
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/applications/%s", testServerURL, appID), nil)
	if err != nil {
		ts.T().Logf("failed to build delete request for app %s: %v", appID, err)
		return
	}
	resp, err := ts.client.Do(req)
	if err != nil {
		ts.T().Logf("failed to delete app %s: %v", appID, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		ts.T().Logf("unexpected status %d deleting app %s: %s", resp.StatusCode, appID, string(body))
	}
}

// obtainClientCredentialsToken requests an access token using the client_credentials
// grant and returns the raw JWT string.
// The /oauth2/ path is treated as a public endpoint by the auth transport, so no admin
// bearer token is injected — client credentials travel via HTTP Basic Auth only.
func (ts *SigningKeyTokenSuite) obtainClientCredentialsToken(clientID, clientSecret string) string {
	reqBody := strings.NewReader("grant_type=client_credentials")
	req, err := http.NewRequest("POST", testServerURL+"/oauth2/token", reqBody)
	ts.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := ts.client.Do(req)
	ts.Require().NoError(err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	ts.Require().Equal(http.StatusOK, resp.StatusCode,
		"token request failed for client %s: %s", clientID, string(body))

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	ts.Require().NoError(json.Unmarshal(body, &tokenResp))
	ts.Require().NotEmpty(tokenResp.AccessToken,
		"access_token must not be empty in token response")

	return tokenResp.AccessToken
}
