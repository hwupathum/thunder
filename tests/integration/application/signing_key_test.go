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

package application

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/asgardeo/thunder/tests/integration/testutils"
	"github.com/stretchr/testify/suite"
)

const (
	signingKeyValidID   = "default-key"
	signingKeyInvalidID = "nonexistent-signing-key"
	signingKeyErrorCode = "APP-1031"
)

// SigningKeyTestSuite tests per-application JWT signing key selection.
type SigningKeyTestSuite struct {
	suite.Suite
	client *http.Client
}

func TestSigningKeyTestSuite(t *testing.T) {
	suite.Run(t, new(SigningKeyTestSuite))
}

func (ts *SigningKeyTestSuite) SetupSuite() {
	ts.client = testutils.GetHTTPClient()
}

// TestCreateApplicationWithValidSigningKeyID verifies that an application can be created
// with a valid signing_key_id and that the field is persisted and returned.
func (ts *SigningKeyTestSuite) TestCreateApplicationWithValidSigningKeyID() {
	app := ts.buildApp("signing-key-create-valid", signingKeyValidID)

	appID, respBody, statusCode := ts.sendCreateApplication(app)
	ts.Require().Equal(http.StatusCreated, statusCode,
		"expected 201 Created when signing_key_id is valid, got: %s", string(respBody))
	ts.Require().NotEmpty(appID)
	defer deleteApplication(appID) //nolint:errcheck

	// Verify the field is returned in the create response.
	var created Application
	ts.Require().NoError(json.Unmarshal(respBody, &created))
	ts.Require().NotEmpty(created.InboundAuthConfig)
	cfg := created.InboundAuthConfig[0].OAuthAppConfig
	ts.Require().NotNil(cfg)
	ts.Assert().Equal(signingKeyValidID, cfg.SigningKeyID,
		"signing_key_id should be returned in create response")

	// Verify the field is persisted when getting the application.
	retrieved, err := getApplicationByID(appID)
	ts.Require().NoError(err)
	ts.Require().NotEmpty(retrieved.InboundAuthConfig)
	retrievedCfg := retrieved.InboundAuthConfig[0].OAuthAppConfig
	ts.Require().NotNil(retrievedCfg)
	ts.Assert().Equal(signingKeyValidID, retrievedCfg.SigningKeyID,
		"signing_key_id should be persisted and returned by GET")
}

// TestCreateApplicationWithInvalidSigningKeyID verifies that creating an application with
// an unknown signing_key_id is rejected with a 400 and error code APP-1031.
func (ts *SigningKeyTestSuite) TestCreateApplicationWithInvalidSigningKeyID() {
	app := ts.buildApp("signing-key-create-invalid", signingKeyInvalidID)

	_, respBody, statusCode := ts.sendCreateApplication(app)
	ts.Assert().Equal(http.StatusBadRequest, statusCode,
		"expected 400 Bad Request when signing_key_id is invalid")

	var errResp struct {
		Code string `json:"code"`
	}
	ts.Require().NoError(json.Unmarshal(respBody, &errResp))
	ts.Assert().Equal(signingKeyErrorCode, errResp.Code,
		"expected error code %s for invalid signing_key_id", signingKeyErrorCode)
}

// TestUpdateApplicationWithValidSigningKeyID verifies that an existing application can be
// updated to set a valid signing_key_id, and the field is returned in the update response.
func (ts *SigningKeyTestSuite) TestUpdateApplicationWithValidSigningKeyID() {
	// Create an app without signing_key_id first.
	app := ts.buildApp("signing-key-update-valid", "")
	appID, _, statusCode := ts.sendCreateApplication(app)
	ts.Require().Equal(http.StatusCreated, statusCode)
	ts.Require().NotEmpty(appID)
	defer deleteApplication(appID) //nolint:errcheck

	// Now update the app to add a valid signing_key_id.
	app.InboundAuthConfig[0].OAuthAppConfig.SigningKeyID = signingKeyValidID
	app.ID = appID
	respBody, updateStatus := ts.sendUpdateApplication(appID, app)
	ts.Require().Equal(http.StatusOK, updateStatus,
		"expected 200 OK when updating with valid signing_key_id, got: %s", string(respBody))

	var updated Application
	ts.Require().NoError(json.Unmarshal(respBody, &updated))
	ts.Require().NotEmpty(updated.InboundAuthConfig)
	cfg := updated.InboundAuthConfig[0].OAuthAppConfig
	ts.Require().NotNil(cfg)
	ts.Assert().Equal(signingKeyValidID, cfg.SigningKeyID,
		"signing_key_id should be returned in update response")
}

// TestUpdateApplicationWithInvalidSigningKeyID verifies that updating an application with
// an unknown signing_key_id is rejected with a 400 and error code APP-1031.
func (ts *SigningKeyTestSuite) TestUpdateApplicationWithInvalidSigningKeyID() {
	// Create a valid app first.
	app := ts.buildApp("signing-key-update-invalid", "")
	appID, _, statusCode := ts.sendCreateApplication(app)
	ts.Require().Equal(http.StatusCreated, statusCode)
	ts.Require().NotEmpty(appID)
	defer deleteApplication(appID) //nolint:errcheck

	// Attempt to update with an invalid signing_key_id.
	app.InboundAuthConfig[0].OAuthAppConfig.SigningKeyID = signingKeyInvalidID
	app.ID = appID
	respBody, updateStatus := ts.sendUpdateApplication(appID, app)
	ts.Assert().Equal(http.StatusBadRequest, updateStatus,
		"expected 400 Bad Request when updating with invalid signing_key_id")

	var errResp struct {
		Code string `json:"code"`
	}
	ts.Require().NoError(json.Unmarshal(respBody, &errResp))
	ts.Assert().Equal(signingKeyErrorCode, errResp.Code,
		"expected error code %s for invalid signing_key_id update", signingKeyErrorCode)
}

// TestCreateApplicationWithoutSigningKeyID verifies that an application created without a
// signing_key_id has an empty signing_key_id in the API response (backward compatibility).
func (ts *SigningKeyTestSuite) TestCreateApplicationWithoutSigningKeyID() {
	app := ts.buildApp("signing-key-absent", "")

	appID, _, statusCode := ts.sendCreateApplication(app)
	ts.Require().Equal(http.StatusCreated, statusCode)
	ts.Require().NotEmpty(appID)
	defer deleteApplication(appID) //nolint:errcheck

	retrieved, err := getApplicationByID(appID)
	ts.Require().NoError(err)
	ts.Require().NotEmpty(retrieved.InboundAuthConfig)
	cfg := retrieved.InboundAuthConfig[0].OAuthAppConfig
	ts.Require().NotNil(cfg)
	ts.Assert().Empty(cfg.SigningKeyID,
		"signing_key_id should be empty when not set (backward compatible behaviour)")
}

// buildApp constructs a minimal OAuth2 application payload for signing key tests.
// clientIDSuffix is appended to the client ID to ensure uniqueness per sub-test.
func (ts *SigningKeyTestSuite) buildApp(clientIDSuffix, signingKeyID string) Application {
	return Application{
		Name:                      "SigningKeyTest-" + clientIDSuffix,
		Description:               "Integration test for per-app JWT signing key",
		IsRegistrationFlowEnabled: false,
		InboundAuthConfig: []InboundAuthConfig{
			{
				Type: "oauth2",
				OAuthAppConfig: &OAuthAppConfig{
					ClientID:                "sk_test_" + clientIDSuffix,
					ClientSecret:            "sk_test_secret_" + clientIDSuffix,
					RedirectURIs:            []string{"https://localhost/callback"},
					GrantTypes:              []string{"client_credentials"},
					ResponseTypes:           []string{},
					TokenEndpointAuthMethod: "client_secret_basic",
					SigningKeyID:            signingKeyID,
				},
			},
		},
	}
}

// sendCreateApplication posts an application creation request and returns the app ID,
// raw response body, and HTTP status code.
func (ts *SigningKeyTestSuite) sendCreateApplication(app Application) (string, []byte, int) {
	appJSON, err := json.Marshal(app)
	ts.Require().NoError(err)

	req, err := http.NewRequest("POST", testServerURL+"/applications", bytes.NewReader(appJSON))
	ts.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.client.Do(req)
	ts.Require().NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	ts.Require().NoError(err)

	if resp.StatusCode == http.StatusCreated {
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &created); err == nil {
			return created.ID, body, resp.StatusCode
		}
	}

	return "", body, resp.StatusCode
}

// sendUpdateApplication sends a PUT request to update an application and returns the
// raw response body and HTTP status code.
func (ts *SigningKeyTestSuite) sendUpdateApplication(appID string, app Application) ([]byte, int) {
	appJSON, err := json.Marshal(app)
	ts.Require().NoError(err)

	req, err := http.NewRequest("PUT", testServerURL+"/applications/"+appID, bytes.NewReader(appJSON))
	ts.Require().NoError(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ts.client.Do(req)
	ts.Require().NoError(err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	ts.Require().NoError(err)

	return body, resp.StatusCode
}
