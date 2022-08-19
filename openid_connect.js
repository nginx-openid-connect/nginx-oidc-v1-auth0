/*
 * JavaScript functions for providing OpenID Connect with NGINX Plus
 * 
 * Copyright (C) 2020 Nginx, Inc.
 */
var newSession = false; // Used by oidcAuth() and validateIdToken()

export default {
    auth,
    codeExchange,
    validateIdToken,
    logout,
    redirectPostLogin,
    redirectPostLogout,
    testAccessTokenPayload,
    testExtractToken,
    testIdTokenPayload
};

function retryOriginalRequest(r) {
    delete r.headersOut["WWW-Authenticate"]; // Remove evidence of original failed auth_jwt
    r.internalRedirect(r.variables.uri + r.variables.is_args + (r.variables.args || ''));
}

// If the ID token has not been synced yet, poll the variable every 100ms until
// get a value or after a timeout.
function waitForSessionSync(r, timeLeft) {
    if (r.variables.session_jwt) {
        retryOriginalRequest(r);
    } else if (timeLeft > 0) {
        setTimeout(waitForSessionSync, 100, r, timeLeft - 100);
    } else {
        auth(r, true);
    }
}

function auth(r, afterSyncCheck) {
    // If a cookie was sent but the ID token is not in the key-value database, wait for the token to be in sync.
    if (r.variables.cookie_auth_token && !r.variables.session_jwt && !afterSyncCheck && r.variables.zone_sync_leeway > 0) {
        waitForSessionSync(r, r.variables.zone_sync_leeway);
        return;
    }

    if (!r.variables.refresh_token || r.variables.refresh_token == "-") {
        newSession = true;

        // Check we have all necessary configuration variables (referenced only by njs)
        var oidcConfigurables = ["authz_endpoint", "scopes", "hmac_key", "cookie_flags"];
        var missingConfig = [];
        for (var i in oidcConfigurables) {
            if (!r.variables["oidc_" + oidcConfigurables[i]] || r.variables["oidc_" + oidcConfigurables[i]] == "") {
                missingConfig.push(oidcConfigurables[i]);
            }
        }
        if (missingConfig.length) {
            r.error("OIDC missing configuration variables: $oidc_" + missingConfig.join(" $oidc_"));
            r.return(500, r.variables.internal_error_message);
            return;
        }
        // Redirect the client to the IdP login page with the cookies we need for state
        r.return(302, r.variables.oidc_authz_endpoint + getAuthZArgs(r));
        return;
    }
    
    // Pass the refresh token to the /_refresh location so that it can be
    // proxied to the IdP in exchange for a new id_token
    r.subrequest("/_refresh", "token=" + r.variables.refresh_token,
        function(reply) {
            if (reply.status != 200) {
                // Refresh request failed, log the reason
                var error_log = "OIDC refresh failure";
                if (reply.status == 504) {
                    error_log += ", timeout waiting for IdP";
                } else if (reply.status == 400) {
                    try {
                        var errorset = JSON.parse(reply.responseBody);
                        error_log += ": " + errorset.error + " " + errorset.error_description;
                    } catch (e) {
                        error_log += ": " + reply.responseBody;
                    }
                } else {
                    error_log += " "  + reply.status;
                }
                r.error(error_log);

                // Clear the refresh token, try again
                r.variables.refresh_token = "-";
                r.return(302, r.variables.request_uri);
                return;
            }

            // Refresh request returned 200, check response
            try {
                var tokenset = JSON.parse(reply.responseBody);
                if (!tokenset.id_token) {
                    r.error("OIDC refresh response did not include id_token");
                    if (tokenset.error) {
                        r.error("OIDC " + tokenset.error + " " + tokenset.error_description);
                    }
                    r.variables.refresh_token = "-";
                    r.return(302, r.variables.request_uri);
                    return;
                }

                // Send the new ID Token to auth_jwt location for validation
                r.subrequest("/_id_token_validation", "token=" + tokenset.id_token,
                    function(reply) {
                        if (reply.status != 204) {
                            r.variables.refresh_token = "-";
                            r.return(302, r.variables.request_uri);
                            return;
                        }

                        // ID Token is valid, update keyval
                        r.log("OIDC refresh success, updating id_token for " + r.variables.cookie_auth_token);
                        r.variables.session_jwt = tokenset.id_token; // Update key-value store
                        r.variables.access_token = tokenset.access_token; // Update key-value store

                        // Update refresh token (if we got a new one)
                        if (r.variables.refresh_token != tokenset.refresh_token) {
                            r.log("OIDC replacing previous refresh token (" + r.variables.refresh_token + ") with new value: " + tokenset.refresh_token);
                            r.variables.refresh_token = tokenset.refresh_token; // Update key-value store
                        }

                        retryOriginalRequest(r); // Continue processing original request
                    }
                );
            } catch (e) {
                r.variables.refresh_token = "-";
                r.return(302, r.variables.request_uri);
                return;
            }
        }
    );
}

function codeExchange(r) {
    // First check that we received an authorization code from the IdP
    if (r.variables.arg_code == undefined || r.variables.arg_code.length == 0) {
        if (r.variables.arg_error) {
            r.error("OIDC error receiving authorization code from IdP: " + r.variables.arg_error_description);
        } else {
            r.error("OIDC expected authorization code from IdP but received: " + r.uri);
        }
        r.return(502);
        return;
    }

    // Pass the authorization code to the /_token location so that it can be
    // proxied to the IdP in exchange for a JWT
    r.subrequest("/_token",idpClientAuth(r), function(reply) {
            if (reply.status == 504) {
                r.error("OIDC timeout connecting to IdP when sending authorization code");
                r.return(504);
                return;
            }

            if (reply.status != 200) {
                try {
                    var errorset = JSON.parse(reply.responseBody);
                    if (errorset.error) {
                        r.error("OIDC error from IdP when sending authorization code: " + errorset.error + ", " + errorset.error_description);
                    } else {
                        r.error("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.responseBody);
                    }
                } catch (e) {
                    r.error("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.responseBody);
                }
                r.return(502);
                return;
            }

            // Code exchange returned 200, check for errors
            try {
                var tokenset = JSON.parse(reply.responseBody);
                if (tokenset.error) {
                    r.error("OIDC " + tokenset.error + " " + tokenset.error_description);
                    r.return(500);
                    return;
                }

                // Send the ID Token to auth_jwt location for validation
                r.subrequest("/_id_token_validation", "token=" + tokenset.id_token,
                    function(reply) {
                        if (reply.status != 204) {
                            r.return(500); // validateIdToken() will log errors
                            return;
                        }

                        // If the response includes a refresh token then store it
                        if (tokenset.refresh_token) {
                            r.variables.new_refresh = tokenset.refresh_token; // Create key-value store entry
                            r.log("OIDC refresh token stored");
                        } else {
                            r.warn("OIDC no refresh token");
                        }

                        // Add opaque token to keyval session store
                        r.log("OIDC success, creating session " + r.variables.request_id);
                        r.variables.new_session = tokenset.id_token; // Create key-value store entry
                        r.variables.new_access_token = tokenset.access_token;
                        r.headersOut["Set-Cookie"] = "auth_token=" + r.variables.request_id + "; " + r.variables.oidc_cookie_flags;
                        r.return(302, r.variables.redirect_base + r.variables.cookie_auth_redir);
                   }
                );
            } catch (e) {
                r.error("OIDC authorization code sent but token response is not JSON. " + reply.responseBody);
                r.return(502);
            }
        }
    );
}

function validateIdToken(r) {
    // Check mandatory claims
    var required_claims = ["iat", "iss", "sub"]; // aud is checked separately
    var missing_claims = [];
    for (var i in required_claims) {
        if (r.variables["jwt_claim_" + required_claims[i]].length == 0 ) {
            missing_claims.push(required_claims[i]);
        }
    }
    if (r.variables.jwt_audience.length == 0) missing_claims.push("aud");
    if (missing_claims.length) {
        r.error("OIDC ID Token validation error: missing claim(s) " + missing_claims.join(" "));
        r.return(403);
        return;
    }
    var validToken = true;

    // Check iat is a positive integer
    var iat = Math.floor(Number(r.variables.jwt_claim_iat));
    if (String(iat) != r.variables.jwt_claim_iat || iat < 1) {
        r.error("OIDC ID Token validation error: iat claim is not a valid number");
        validToken = false;
    }

    // Audience matching
    var aud = r.variables.jwt_audience.split(",");
    if (!aud.includes(r.variables.oidc_client)) {
        r.error("OIDC ID Token validation error: aud claim (" + r.variables.jwt_audience + ") does not include configured $oidc_client (" + r.variables.oidc_client + ")");
        validToken = false;
    }

    // If we receive a nonce in the ID Token then we will use the auth_nonce cookies
    // to check that the JWT can be validated as being directly related to the
    // original request by this client. This mitigates against token replay attacks.
    if (newSession) {
        var client_nonce_hash = "";
        if (r.variables.cookie_auth_nonce) {
            var c = require('crypto');
            var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(r.variables.cookie_auth_nonce);
            client_nonce_hash = h.digest('base64url');
        }
        if (r.variables.jwt_claim_nonce != client_nonce_hash) {
            r.error("OIDC ID Token validation error: nonce from token (" + r.variables.jwt_claim_nonce + ") does not match client (" + client_nonce_hash + ")");
            validToken = false;
        }
    }

    if (validToken) {
        r.return(204);
    } else {
        r.return(403);
    }
}

function getAuthZArgs(r) {
    // Choose a nonce for this flow for the client, and hash it for the IdP
    var noncePlain = r.variables.request_id;
    var c = require('crypto');
    var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(noncePlain);
    var nonceHash = h.digest('base64url');
    var audArg = '&audience=' + 'https://' + r.variables.idp_domain + '/api/v2/';
    var authZArgs = "?response_type=code&scope=" + r.variables.oidc_scopes + "&client_id=" + r.variables.oidc_client + "&redirect_uri="+ r.variables.redirect_base + r.variables.redir_location + audArg + "&nonce=" + nonceHash;

    r.headersOut['Set-Cookie'] = [
        "auth_redir=" + r.variables.request_uri + "; " + r.variables.oidc_cookie_flags,
        "auth_nonce=" + noncePlain + "; " + r.variables.oidc_cookie_flags
    ];

    if ( r.variables.oidc_pkce_enable == 1 ) {
        var pkce_code_verifier = c.createHmac('sha256', r.variables.oidc_hmac_key).update(String(Math.random())).digest('hex');
        r.variables.pkce_id = c.createHash('sha256').update(String(Math.random())).digest('base64url');
        var pkce_code_challenge = c.createHash('sha256').update(pkce_code_verifier).digest('base64url');
        r.variables.pkce_code_verifier = pkce_code_verifier;

        authZArgs += "&code_challenge_method=S256&code_challenge=" + pkce_code_challenge + "&state=" + r.variables.pkce_id;
    } else {
        authZArgs += "&state=0";
    }
    return authZArgs;
}

function idpClientAuth(r) {
    // If PKCE is enabled we have to use the code_verifier
    if ( r.variables.oidc_pkce_enable == 1 ) {
        r.variables.pkce_id = r.variables.arg_state;
        return "code=" + r.variables.arg_code + "&code_verifier=" + r.variables.pkce_code_verifier;
    } else {
        return "code=" + r.variables.arg_code + "&client_secret=" + r.variables.oidc_client_secret;
    }   
}

// Redirect URI after logging in the IDP.
function redirectPostLogin(r) {
    r.return(302, r.variables.redirect_base + getIDTokenArgsAfterLogin(r));
}

// Get query parameter of ID token after sucessful login:
//
// - For the variable of `returnTokenToClientOnLogin` of the APIM, this config
//   is only effective for /login endpoint. By default, our implementation MUST
//   not return any token back to the client app. 
// - If its configured it can send id_token in the request uri as 
//   `?id_token=sdfsdfdsfs` after successful login. 
//
function getIDTokenArgsAfterLogin(r) {
    if (r.variables.return_token_to_client_on_login == 'id_token') {
        return '?id_token=' + r.variables.id_token;
    }
    return '';
}

// Redirect URI after logged-out from the IDP.
function redirectPostLogout(r) {
    r.return(302, r.variables.post_logout_return_uri);
}


// RP-Initiated or Custom Logout w/ IDP:
// 
// - An RP requests that the IDP log out the end-user by redirecting the
//   end-user's User Agent to the IDP's Logout endpoint.
// - TODO: Handle custom logout parameters if IDP doesn't support standard spec
//         of 'OpenID Connect RP-Initiated Logout 1.0'.
// - https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
// - https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout
// function logout(r) {
//     r.log("OIDC logout for " + r.variables.cookie_auth_token);
//     r.variables.session_jwt = "-";
//     r.variables.refresh_token = "-";
//     r.return(302, r.variables.oidc_logout_redirect);
// }

function logout(r) {
    r.log('OIDC logout for ' + r.variables.request_id);
    var logout_endpoint = generateCustomEndpoint(r,
        r.variables.oidc_logout_endpoint,
        r.variables.oidc_logout_path_params_enable,
        r.variables.oidc_logout_path_params
    );
    var queryParams = '';
    var idToken = r.variables.session_jwt;

    // OIDC RP-initiated logout.
    if (r.variables.oidc_logout_query_params_enable == 0) {
        queryParams = getRPInitiatedLogoutArgs(r, idToken);

    // Call the IDP logout endpoint with custom query parameters
    // if the IDP doesn't support RP-initiated logout.
    } else {
        queryParams = generateQueryParams(r.variables.oidc_logout_query_params);
    }
    r.variables.request_id    = '-';
    r.variables.session_jwt   = '-';
    r.variables.access_token  = '-';
    r.variables.refresh_token = '-';
    r.return(302, logout_endpoint + queryParams);
}

// Generate custom endpoint using path parameters if the option is enable.
// Otherwise, return the original endpoint.
//
// [Example 1]
// - Input : "https://{my-app}.okta.com/oauth2/{version}/logout"
//   + {my-app}  -> 'dev-9590480'
//   + {version} -> 'v1'
// - Result: "https://dev-9590480.okta.okta.com/oauth2/v1/logout"
//
// [Example 2]
// - Input : "https://{my-app}.okta.com/oauth2/{version}/authorize"
//   + {my-app}  -> 'dev-9590480'
//   + {version} -> 'v1'
// - Result: "https://dev-9590480.okta.okta.com/oauth2/v1/authorize"
//
function generateCustomEndpoint(r, uri, isEnableCustomPath, paths) {
    if (isEnableCustomPath == 0) {
        return uri;
    }
    var res   = '';
    var key   = '';
    var isKey = false;
    r.log('### paths: ' + paths)
    var items = JSON.parse(paths);
    for (var i = 0; i < uri.length; i++) {
        switch (uri[i]) {
            case '{': 
                isKey = true; 
                break;
            case '}': 
                res  += items[key]
                key   = '';
                isKey = false; 
                break;
            default : 
                if (!isKey) {
                    res += uri[i];
                } else {
                    key += uri[i];
                }
        }
    }
    r.log('generated an endpoint using path params: ' + res)
    return res;
}

// Get query params for RP-initiated logout:
//
// - https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
// - https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout
//
function getRPInitiatedLogoutArgs(r, idToken) {
    return '?post_logout_redirect_uri=' + r.variables.redirect_base
                                        + r.variables.oidc_logout_redirect +
           '&id_token_hint='            + idToken;
}

// Generate custom query parameters from JSON object
function generateQueryParams(obj) {
    var items = JSON.parse(obj);
    var args = '?'
    for (var key in items) {
        args += key + '=' + items[key] + '&'
    }
    return args.slice(0, -1)
}

// Extract ID/access token from the request header.
function extractToken(r, key, is_bearer, validation_uri, msg) {
    var token = '';
    try {
        var headers = r.headersIn[key].split(' ');
        if (is_bearer) {
            if (headers[0] === 'Bearer') {
                token = headers[1]
            } else {
                msg += `, "` + key + `": "N/A"`;
                return [true, msg];
            }
        } else {
            token = headers[0]
        }
        if (!isValidToken(r, validation_uri, token)) {
            msg += `, "` + key + `": "invalid"}\n`;
            r.return(401, msg);
            return [false, msg];
        } else {
            msg += `, "` + key + `": "` + token + `"`;
        }
    } catch (e) {
        msg += `, "` + key + `": "N/A"`;
    }
    return [true, msg];
}

// Return JWT header and payload
function jwt(r, token) {
    var parts = token.split('.').slice(0,2)
        .map(v=>Buffer.from(v, 'base64url').toString())
        .map(JSON.parse);
    return { 
        headers: parts[0], 
        payload: parts[1] 
    };
}

// Test for extracting bearer token from the header of API request.
function testExtractToken (r) {
    var msg = `{
        "message": "This is to show which token is part of proxy header(s) in a server app.",
        "uri":"` + r.variables.request_uri + `"`;
    var res = extractToken(r, 'Authorization', true, '/_access_token_validation', msg)
    if (!res[0]) {
        return 
    }
    msg = res[1]

    var res = extractToken(r, 'x-id-token', false, '/_id_token_validation', msg)
    if (!res[0]) {
        return 
    }
    msg = res[1]

    var body = msg + '}\n';
    r.return(200, body);
}

// Test for extracting sub, subgroups (custom claim) from token
function testTokenBodyWithCustomClaim(r, token) {
    var res = jwt(r, token)
    var msgToken = `"token": "` + token + `"`
    var msgSub = `"sub": "` + res.payload.sub + `"`
    var msgSubGroups = `"subgroups": "` + res.payload.subgroups + `"`
    var body = `{` + msgToken + `,` + msgSub + `,` + msgSubGroups + `}`
    return body
}

// Return access token details with custom claim for testing
function testAccessTokenPayload(r) {
    r.return(200, testTokenBodyWithCustomClaim(r, r.variables.access_token))
}

// Return ID token details with custom claim for testing
function testIdTokenPayload(r) {
    r.return(200, testTokenBodyWithCustomClaim(r, r.variables.session_jwt))
}
