# Test Case Documentation

This document contains descriptions of the built-in test cases as well as documentation for their result values that are integrated into the report files..

## `body.CompareHTTPBodyToSchema`

Check whether the HTTP body of an API response matches a given JSON schema definition.

### Issue Types

- `comparison_match`: Body in the HTTP response matches the given JSON schema definition.
- `comparison_different`: Body in the HTTP response differs from the given JSON schema definition.

### Result Value

Example:

```json
{
    "valid": true,
    "invalid_subschema": {...}
}
```

Key                 | Description
--------------------|-------------
`valid`             | `true` if the JSON schema matches, else `false`.
`invalid_subschema` | Mismatching subschema if issue type is `comparison_different`.


## `body.CompareHTTPBodyAuthNonauth`

Check the differences in responses for an unauthorized and an authorized API requests. Response bodies
are assumed to be JSON payloads.

### Issue Types

- `comparison_match`: The response to an unauthorized request exactly matches the response to an authorized API request.
- `comparison_different`: The response to an unauthorized request differs from the response to an authorized API request.

### Result Value

Example:

```json
{
    "common_values": ...,
    "unique_values_left": ...,
    "unique_values_right": ...,
}
```

Key                   | Description
----------------------|-------------
`common_values`       | Content found in **both** responses.
`unique_values_left`  | Unique values found in the **unauthorized** response.
`unique_values_right` | Unique values found in the **authorized** response.


## `headers.FindCustomHeaders`

Search for non-standardized HTTP headers in an API response.

### Issue Types

- `analysis_none`: No custom headers found in the API response.
- `analysis_candidate`: One or more custom headers found in the API response.

### Result Value

Example:

```json
{
    "X-Rate-Limit": 600,
}
```

`value` contains all found custom header IDs as keys with their respective payload as values.


## `headers.FindSecurityHeaders`

Search for security-relevant HTTP headers in an API response. This includes standardized headers as well
as commonly used on-standard headers such as `X-FRAME-OPTIONS`.

### Issue Types

- `analysis_none`: No security headers found in the API response.
- `analysis_candidate`: One or more security headers found in the API response.

### Result Value

Example:

```json
{
    "X-Frame-Options": "DENY",
}
```

`value` contains all found security header IDs as keys with their respective payload as values.


## `headers.MetaCompareHeaders`

Compare the results of two checks for the test cases `headers.FindCustomHeaders` or `headers.FindSecurityHeaders`.
This may be used to identity differences in responses across different endpoints.

### Issue Types

- `comparison_match`: Found header IDs **and** header payloads of both checks are an exact match.
- `comparison_different`: Header IDs or header payloads of the two checks are different.

### Result Value

Example:

```json
{
    "left": ...,
    "right": ...,
    "common": ...,
}
```

Key                   | Description
----------------------|-------------
`left`                | Header/payload combinations found in **both** responses.
`right`               | Unique header/payload combinations of the **first** check.
`common`              | Unique header/payload combinations of the **second** check.


## `https.TestHTTPSAvailable`

Check whether an API endpoint can be accessed via HTTPS.

### Issue Types

- `security_okay`: API response contains a 2XX response code.
- `security_problem`: API response contains a 3XX response code (redirection). If `--propose` is active, the redirect URL is automatically tested with this test case.
- `security_flaw`: API response contains any other response code. It's assumed that the API endpoint is inaccessible via HTTPS.

### Result Value

Example:

```json
{
    "status_code": 301,
    "redirect": true,
    "redirect_url": https://api.example.com/redirect,
}
```

Key                   | Description
----------------------|-------------
`status_code`         | Status code of the API response.
`redirect`            | `true` if the API request is answered with a redirect, else `false`.
`redirect_url`        | If `redirect` is true, contains the redirect URL.


## `https.TestHTTPAvailable`

Check whether an API endpoint can be accessed via plain HTTP.

### Issue Types

- `security_okay`: API response **does not** contains a 2XX response code (i.e. it cannot be accessed with plain HTTP).
- `security_problem`: API response contains a 3XX response code (redirection) and the redirect URL does not start with `https`. If `--propose` is active, the redirect URL is automatically tested with the `https.TestHTTPSAvailable` test case.
- `security_flaw`: API response contains a 2XX response code.. It's assumed that the API endpoint is accessible via plain HTTP.

### Result Value

Example:

```json
{
    "status_code": 301,
    "redirect": true,
    "redirect_url": https://api.example.com/redirect,
}
```

Key                   | Description
----------------------|-------------
`status_code`         | Status code of the API response.
`redirect`            | `true` if the API request is answered with a redirect, else `false`.
`redirect_url`        | If `redirect` is true, contains the redirect URL.


## `https.TestDescriptionURLs`

Check which protocol schemes are used for the defined server URLs inside the API description. This test case explicitely looks
for HTTP and HTTPS URLs.

### Issue Types

- `security_okay`: Server definitions only contain URLs with HTTPS as protocol scheme.
- `security_problem`: Server definitions contain URLs with missing or unknown protocol schemes.
- `security_flaw`: Server definitions contain URLs with HTTP as protocol scheme.

### Result Value

Example:

```json
{
    "http_urls": [...],
    "https_urls": [...],
    "unknown_scheme_urls": [...],
    "paths_with_servers": [...],
}
```

Key                   | Description
----------------------|-------------
`http_urls`           | HTTP URLs found in the API description.
`https_urls`          | HTTPS URLs found in the API description.
`unknown_scheme_urls` | URLs with missing/unknown protocol schemes found in the API description.
`paths_with_servers`  | IDs of paths that have a custom server definiton.


## `misc.GetHeaders`

Get specific response headers from an API response to a generic API endpoint.

### Issue Types

- `analysis_candidate`: Always used.

### Result Value

Example:

Example:

```json
{
    "X-Frame-Options": "DENY",
}
```

`value` contains the requested header ID/payload of the API response.


## `misc.GetParameters`

Get specific parameters from the JSON body of an API response to a generic API endpoint.

### Issue Types

- `analysis_candidate`: Always used.

### Result Value

Example:

Example:

```json
{
    "example": {},
}
```

`value` contains the requested parameter values in the API response.


## `resources.TestObjectIDInvalidUserAccess`

Check if an object (resource with ID) is accessible without providing a sufficient access level (= unauthorized access).

### Issue Types

- `security_okay`: The object cannot be accessed with the specified access level (response code `401`, `403` or `404`).
- `security_problem`: The object cannot be accessed with the specified access level, but the API response's response code is different than expected (e.g. a 5XX code or a redirect).
- `security_flaw`: The object is accessible with the specified access level.

### Result Value

Example:

```json
{
    "status_code": 200,
    "object_id": "12345",
    "object_name": "test",
    "response_body": {...},
}
```

Key                   | Description
----------------------|-------------
`status_code`         | Status code of the API response.
`object_id`           | ID of the object (if specified).
`object_name`         | Name of the object (if specified).
`response_body`       | Content of the object if it's a JSON object, else `null`.


## `resources.CountParameterRequiredRefs`

Determine frequency of required request parameters in an OpenAPI description. This test case assumes that parameters
with the same name reference the same parameter.

### Issue Types

- `analysis_none`: No required request parameters found.
- `analysis_candidate`: At least one required request parameter found.

### Result Value

Example:

```json
{
    "test": 123
}
```

`value` contains the request parameter IDs as keys and their frequency as value (e.g. the parameter `"test"` is required at 123 endpoints). The result is ordered descending by frequency.


## `resources.FindIDParameters`

Search for parameters that could be resource IDs or other object references in an API description. It searches for parameters with the substrings `id`, `name` or `obj` in their name.

### Issue Types

- `analysis_none`: No candidates for ID parameters found.
- `analysis_candidate`: At least one candidate for ID parameters found.

### Result Value

Example:

```json
{
    "unique_parameters": [...],
    "unique_parameter_count": {...}
}
```

Key                      | Description
-------------------------|-------------
`unique_parameters`      | Unique ID parameter names found.
`unique_parameter_count` | Key-value pairs of parameters by their overall frequency.


## `resources.FindParameterReturns`

Search for endpoints in an API description which return specified parameters in their API response.

### Issue Types

- `analysis_none`: No candidate endpoints the specified parameters found.
- `analysis_candidate`: At least one endpoint that returns the specified parameters found.

### Result Value

Example:

```json
{
    "endpoints": {...}
}
```

Key              | Description
-----------------|-------------
`endpoints`      | Information about the endpoints that return the specified parameters.


## `resources.FindSecurityParameters`

Search for parameters and endpoints that could reveal sensitive security information in an API description, e.g. parameters that reveal access control data or other information for authentication/authorization. It searches for endpoints and parameters with the substrings `token`, `key`, `auth`, `pass`, `pw` or `session` in their value string.

### Issue Types

- `analysis_none`: No candidate parameters/endpoints found.
- `analysis_candidate`: At least one parameter/endpoint found.

### Result Value

Example:

```json
{
    "security_descriptions": [...],
    "security_params": [...],
    "endpoints": {...},
}
```

Key                      | Description
-------------------------|-------------
`security_descriptions`  | Found descriptions that indicate that the endpoint reveals sensitive security informative.
`security_params`        | Found parameters that could reveal sensitive security informative.
`endpoints`              | Information about the endpoints that return the candidate parameters.


## `resources.FindDuplicateParameters`

Search for parameters that are returned at more than one endpoint in an API description. This can be used to find alternative access to a specific parameter.

### Issue Types

- `analysis_none`: No candidate parameters found.
- `analysis_candidate`: At least one duplicate parameter found.

### Result Value

Example:

```json
{
    "params_count": 3,
    "params": {...},
    "components_count": 3,
    "components": {...}
}
```

Key                      | Description
-------------------------|-------------
`params_count`           | Number of duplicate parameters.
`params`                 | Name and endpoint locations of the duplicate parameters.
`components_count`       | Number of duplicate OpenAPI components.
`components`             | Name and endpoint locations of the OpenAPI components.


## `scopes.CheckScopesEndpoint`

Check if an endpoint can be accessed with a specified authorization level (using OAuth2 scopes).

### Issue Types

- `analysis_none`: Endpoint **cannot** be accessed with the specified authorization level.
- `analysis_candidate`: Endpoint **can** be accessed with the specified authorization level.

### Result Value

Example:

```json
{
    "accepted": true
}
```

Key                      | Description
-------------------------|-------------
`accepted`               | `true` if the API request is accepted, else `false`.


## `resources.FindDuplicateParameters`

Search for parameters that are returned at more than one endpoint in an API description. This can be used to find alternative access to a specific parameter.

### Issue Types

- `analysis_none`: No candidate parameters found.
- `analysis_candidate`: At least one duplicate parameter found.

### Result Value

Example:

```json
{
    "params_count": 3,
    "params": {...},
    "components_count": 3,
    "components": {...}
}
```

Key                      | Description
-------------------------|-------------
`params_count`           | Number of duplicate parameters.
`params`                 | Name and endpoint locations of the duplicate parameters.
`components_count`       | Number of duplicate OpenAPI components.
`components`             | Name and endpoint locations of the OpenAPI components.


## `scopes.ScopeMappingDescription`

Map OAuth2 scopes to the endpoints they allow access to based on the information in an OpenAPI description.

### Issue Types

- `analysis_candidate`: Always used.

### Result Value

Example:

```json
{
    "user": [...]
}
```

`value` contains the scope names as keys and the endpoints they allow to access as values.


## `scopes.CompareTokenScopesToClientScopes`

Check if an OAuth2 token has more priviledges than should be available to the client that requests the token. This is done by checking if the OAuth2 token has more/different scopes assigned than the client.

### Issue Types

- `security_okay`: OAuth2 token has access to the same or a subset of the scopes available to the client.
- `security_flaw`: OAuth2 token has access to more/different scopes than available to the client.

### Result Value

Example:

```json
{
    "supported_by_client": [...],
    "unsupported_by_client": [...]
}
```

Key                      | Description
-------------------------|-------------
`supported_by_client`    | Scopes available to the client.
`unsupported_by_client`  | Scopes assigned to the OAuth2 token that should not be available to the client.


## `scopes.TestTokenRequestScopeOmit`

Check if and which scopes are assigned to an OAuth2 token if the scope parameter is omitted in an authorization request (as defined in RFC 6749 section 3.3).

### Issue Types

- `analysis_none`: Authorization endpoint denies the token request.
- `analysis_candidate`: Authorization endpoint returns a token.

### Result Value

Example:

```json
{
    "received_scopes": [...]
}
```

Key                  | Description
---------------------|-------------
`received_scopes`    | Scopes assigned to the OAuth2 token


## `scopes.TestRefreshTokenRequestScopeOmit`

Check if and which scopes are assigned to an OAuth2 token if the scope parameter is omitted when refreshing a token (as defined in RFC 6749 section 3.3).

### Issue Types

- `analysis_none`: Authorization endpoint denies the token request.
- `analysis_candidate`: Authorization endpoint returns a token.

### Result Value

Example:

```json
{
    "received_scopes": [...]
}
```

Key                  | Description
---------------------|-------------
`received_scopes`    | Scopes assigned to the OAuth2 token


## `scopes.TestTokenRequestScopeEmpty`

Check if and which scopes are assigned to an OAuth2 token if the scope parameter is an empty string in an authorization request (as defined in RFC 6749 section 3.3).

### Issue Types

- `analysis_none`: Authorization endpoint denies the token request.
- `analysis_candidate`: Authorization endpoint returns a token.

### Result Value

Example:

```json
{
    "received_scopes": [...]
}
```

Key                  | Description
---------------------|-------------
`received_scopes`    | Scopes assigned to the OAuth2 token


## `scopes.TestRefreshTokenRequestScopeEmpty`

Check if and which scopes are assigned to an OAuth2 token if the scope parameter is an empty string when refreshing a token (as defined in RFC 6749 section 3.3).

### Issue Types

- `analysis_none`: Authorization endpoint denies the token request.
- `analysis_candidate`: Authorization endpoint returns a token.

### Result Value

Example:

```json
{
    "received_scopes": [...]
}
```

Key                  | Description
---------------------|-------------
`received_scopes`    | Scopes assigned to the OAuth2 token


## `scopes.TestTokenRequestScopeInvalid`

Check if and which scopes are assigned to an OAuth2 token if the scope parameter does not contain valid scopes values in an authorization request (as defined in RFC 6749 section 3.3). The scope value send to the authorization endpoint is a random string.

### Issue Types

- `analysis_none`: Authorization endpoint denies the token request.
- `analysis_candidate`: Authorization endpoint returns a token.

### Result Value

Example:

```json
{
    "random_number": 1337,
    "scope": "8516bfad8d65603b872d2c4a688135d7",
    "received_scopes": [...]
}
```

Key                  | Description
---------------------|-------------
`random_number`      | Random number which is used to generate the random scope string.
`scope`              | Scope value sent to the authorization endpoint. The value is the hex digest of the SHA256 hash of the random number.
`received_scopes`    | Scopes assigned to the returned OAuth2 token.


## `scopes.TestRefreshTokenRequestScopeOmit`

Check if and which scopes are assigned to an OAuth2 token if the scope parameter does not contain valid scopes values when refreshing a token (as defined in RFC 6749 section 3.3). The scope value send to the authorization endpoint is a random string.

### Issue Types

- `analysis_none`: Authorization endpoint denies the token request.
- `analysis_candidate`: Authorization endpoint returns a token.

### Result Value

Example:

```json
{
    "random_number": 1337,
    "scope": "8516bfad8d65603b872d2c4a688135d7",
    "received_scopes": [...]
}
```

Key                  | Description
---------------------|-------------
`random_number`      | Random number which is used to generate the random scope string.
`scope`              | Scope value sent to the authorization endpoint. The value is the hex digest of the SHA256 hash of the random number.
`received_scopes`    | Scopes assigned to the returned OAuth2 token.


## `scopes.TestReadOAuth2Expiration`

Check the expiration time of an OAuth2 token.

### Issue Types

- `analysis_none`: Authorization endpoint does not provide expiration time information.
- `analysis_candidate`: Authorization endpoint provides expiration time information.

### Result Value

Example:

```json
{
    "vailidity_length": 1337,
    "expires_at": 13372342
}
```

Key                  | Description
---------------------|-------------
`vailidity_length`   | How long the token is valid after its creation (in number of seconds).
`expires_at`         | Time at wich the token expires (in UNIX time).


## `scopes.TestOAuth2Expiration`

Check if the provided token expires after the specified time. The test case send several API requests *after* the token is expired to determine when the API
rejects the token.

### Issue Types

- `security_okay`: Token is not accepted after expiration time.
- `security_problem`: Token is still accepted 1 second after expiration time.
- `security_flaw`: Token is still accepted 60 seconds or later after expiration time.

### Result Value

Example:

```json
{
    "min_validity_time": 0,
}
```

Key                  | Description
---------------------|-------------
`min_validity_time`  | How long the token is accepted after it should have expired (in seconds).


## `scopes.TestDecodeOAuth2JWT`

Check if the OAuth2 Token is a JWT and decode its content.

### Issue Types

- `analysis_none`: Token is not a JWT and cannot be decoded.
- `analysis_candidate`: Token can be decoded.

### Result Value

Example:

```json
{
    "header": "...",
    "payload": "..."
}
```

Key                  | Description
---------------------|-------------
`header`             | Decoded JWT header.
`payload`            | Decoded JWT payload.


## `scopes.TestRefreshTokenRevocation`

Check if refresh tokens are single-use, i.e. they are invalidated after redeeming them once.

### Issue Types

- `security_okay`: Refresh token can only be used once.
- `security_problem`: Refresh token can only be used at least twice.

### Result Value

Example:

```json
{
    "refresh_token": "8516bfad8d65603b872d2c4a688135d7",
    "single_use": true
}
```

Key                  | Description
---------------------|-------------
`refresh_token`      | Refresh token value.
`single_use`         | `true` if the token is single-use, else `false`.


## `undocumented.TestOptionsHTTPMethod`

Checks which HTTP methods/API operations are allowed for a path by sending a request using the `OPTIONS` HTTP method.

### Issue Types

- `analysis_none`: No information about allowed methods in API response.
- `analysis_candidate`: API response indicates allowed methods.

### Result Value

Example:

```json
{
    "claimed": [...],
    "wrong_claims": [...],
    "missing_claims": [...]
}
```

Key                  | Description
---------------------|-------------
`claimed`            | Allowed HTTP methods/API operations according to the API description.
`wrong_claims`       | HTTP methods/API operations in the API description that are missing from the API response claims.
`missing_claims`     | HTTP methods/API operations in the API response claims that are missing in the API description.


## `undocumented.MetaTestOptionsHTTPMethod`

Aggregate the results of `TestOptionsHTTPMethod` by comparing the overall number of wrong/missing claims.

### Issue Types

- `analysis_none`: No wrong or missing claims found for any path.
- `analysis_candidate`: At least one path has wrong or missing claims.

### Result Value

Example:

```json
{
    "affected_paths": 1,
    "skipped_paths": 0,
    "total_wrong_claims": 10,
    "total_missing_claims": 0,
    "paths": [...]
}
```

Key                    | Description
-----------------------|-------------
`affected_paths`       | Number of paths with wrong or missing claims.
`skipped_paths`        | Skipped of paths (if claimed operations are not available).
`total_wrong_claims`   | Total number of wrong claims across all paths.
`total_missing_claims` | Total number of missing claims across all paths.
`paths`                | Paths with wrong or missing claims.


## `undocumented.TestAllowedHTTPMethod`

Check if a defined path supports a specified HTTP method/API operation.

### Issue Types

- `analysis_none`: API request for path does not support the specified HTTP method **and** returns the correct response code `405`.
- `analysis_candidate`: API request for path returns any other response code than `405`.

### Result Value

Example:

```json
{
    "path": "/example/path",
    "http_method": "post",
    "status_code": 200
}
```

Key                  | Description
---------------------|-------------
`path`               | Tested path.
`http_method`        | Requested HTTP method/API operation.
`status_code`        | HTTP response code from the API response.


## `undocumented.MetaTestAllowedHTTPMethod`

Aggregate the results of `TestAllowedHTTPMethod` by comparing the overall number of accepted methods.

### Issue Types

- `analysis_none`: All checks executed with issue type `analysis_none`.
- `analysis_candidate`: At least one check executed with issue type `analysis_candidate`.

### Result Value

Example:

```json
{
    "affected_paths": 1,
    "affected_methods": 1,
    "found_methods": 3
}
```

Key                    | Description
-----------------------|-------------
`affected_paths`       | Number of paths that support undocumented HTTP methods.
`affected_methods`     | Total number of undocumented HTTP methods across all paths.
`found_methods`        | Information about the undocumented methods for each path.
