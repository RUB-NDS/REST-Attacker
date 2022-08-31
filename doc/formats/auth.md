# Authfile

The auth file stores information that is used to authenticate with the service or make authorized requests.
This includes credential information, schemes for creating authenticated/authorized request payloads and
user sessions to retrieve OAuth2 tokens.

The auth file is referenced in the mandatory [info file](info.md). The preferred filename is `credentials.json`.

## Quick Reference

```json
{
    "creds": {
        "client0": {
            "type": "oauth2_client",
            "description": "OAuth Client",
            "client_id": "aabbccddeeff123456789",
            "client_secret": "abcdef12345678998765431fedcba",
            "redirect_uri": "https://localhost:1234/test/",
            "authorization_endpoint": "https://example.com/login/oauth/authorize",
            "token_endpoint": "https://example.com/login/oauth/token",
            "grants": [
                "code",
                "token"
            ],
            "scopes": [
                "user"
            ],
            "flags": []
        }
    },
    "schemes": {
        "scheme0": {
            "type": "header",
            "key_id": "authorization",
            "payload": "token {0}",
            "params": {
                "0": {
                    "id": "access_token",
                    "from": [
                        "token0",
                    ]
                }
            }
        }
    },
    "required_always": {},
    "required_auth": {
        "req0": [
            "scheme0"
        ]
    },
    "users": {
        "user0": {
            "account_id": "user",
            "user_id": "userXYZ",
            "owned_resources": {},
            "allowed_resources": {},
            "sessions": {
                "gbrowser": {
                    "type": "browser",
                    "exec_path": "/usr/bin/chromium",
                    "local_port": "1234"
                }
            },
            "credentials": [
                "client0"
            ]
        }
    }
}
```

## Attributes

Parameter         | Type          | Optional
------------------|---------------|----------
[creds]           | Object        | No
[schemes]         | Object        | No
[users]           | Object        | Yes
required_always   | Object        | Yes
required_auth     | Object        | Yes

[creds](#creds-object)
[schemes](#schemes-object)
[users](#users-object)


**creds**<br>
Credentials for the service defined as [credentials objects](#creds-object). Keys
are used as identifiers for referencing the specific credential object.

**schemes**<br>
Schemes for authenticated/authorized requests defined as [scheme objects](#schemes-object). Keys
are used as identifiers for referencing the specific scheme object.

**required_always**<br>
This attribute can be used to define the minimum required schemes to make requests.

Contains groups of schemes, where each group consists of a list of scheme IDs. At least one scheme per
group should be included in a request. The first scheme ID in each group is internally used as the default
scheme.

*Example:*

```json
{
    "required_unauth": {
        "group0": [
            "header0"
        ],
        "group1": [
            "query0"
            "cookie0"
        ]
    }
}
```

*To make an **unauthenticated/unauthorized** requests, one scheme from `group0` and one scheme from `group1`*
*should be included in the request. For `group0` the only option is using scheme `header0`. For `group1`, we can*
*choose between the schemes `query0` and `cookie0`. By default, the tool chooses the first scheme listed for each*
*group, i.e. the request will include the schemes `header0` and `query0`.*


**required_auth**<br>
This attribute can be used to define the minimum required schemes to make **authenticated/authorized**
requests.

Contains groups of schemes, where each group consists of a list of scheme IDs. At least one scheme per
group should be included in a request. The first scheme ID in each group is internally used as the default
scheme.

*Example:*

```json
{
    "required_auth": {
        "group0": [
            "header0"
        ],
        "group1": [
            "query0"
            "cookie0"
        ]
    }
}
```

*To make an **unauthenticated/unauthorized** requests, one scheme from `group0` and one scheme from `group1`*
*should be included in the request. For `group0` the only option is using scheme `header0`. For `group1`, we can*
*choose between the schemes `query0` and `cookie0`. By default, the tool chooses the first scheme listed for each*
*group, i.e. the request will include the schemes `header0` and `query0`.*


### `creds` Object

Parameter       | Type   | Optional
----------------|--------|----------
type            | String | No
description     | String | Yes
*type-specific* | Any    | -

**type**<br>
Type of credentials. This type determines which additional type-specific parameters are expected to be included in this object
by the tool. Type-specific parameters for each type are linked below.

The following types are currently supported:

- `[oauth2_client](#oauth2-client-type)`: Credentials for an OAuth2 client and information about authorization/token endpoints.
- `[token](#token-type)`: (Access) Tokens
- `[api_key](#api-key-type)`: API Keys/Tokens
- `[basic](#basic-type)`: Credentials for HTTP Basic Authentication (i.e. username/password)

Only the `oauth2_client` currently matters because these credentials are converted to `OAuth2TokenGenerator`s.

**description**<br>
Human-readable description of the credentials.


#### `oauth2_client` Type

Parameter      | Type          | Optional
---------------|---------------|----------
client_id      | String        | No
client_secret  | String        | No
auth_endpoint  | String        | No
token_endpoint | String        | No
redirect_uri   | String        | No
grants         | Array[String] | No
scopes         | Array[String] | Yes

**client_id**<br>
ID of the configured client.

**client_secret**<br>
Secret for the configured client.

**auth_endpoint**<br>
The OAuth2 authorization endpoint of the service.

**token_endpoint**<br>
The OAuth2 token endpoint of the service.

**redirect_uri**<br>
Redirect URI configured for this client. Currently only one redirect URI can be specified here.

**grants**<br>
Grants supported by the client. The tool can understand the OAuth2 grant types `code`, `token` and `refresh_token`.

**scopes**<br>
Scopes supported by the client. If not present, the tool assumes that the client supports all scopes listed in
the [info file](info.md). If no scopes were specified there, checks that require a list of claimed scopes
may be skipped by the tool.


#### `token` Type

Parameter      | Type          | Optional
---------------|---------------|----------
access_token   | String        | No
expires_at     | Number        | Yes
scopes         | Array[String] | Yes

**access_token**<br>
Access token value.

**expires_in**<br>
UNIX time of the expiration date of the token.

**scopes**<br>
Scopes assigned to the access token. If not present, the tool assumes that the access tokens is valid for all scopes.


#### `api_key` Type

Parameter      | Type          | Optional
---------------|---------------|----------
key            | String        | No
client_id      | String        | Yes

**key**<br>
API key value.

**client_id**<br>
ID of the client for which the API key was generated.


### `basic` Type

Parameter      | Type          | Optional
---------------|---------------|----------
username       | String        | No
password       | String        | No

**username**<br>
Username of the user.

**password**<br>
Password of the user.


#### `users` Object

Parameter         | Type          | Optional
------------------|---------------|----------
account_id        | String        | No
user_id           | String        | No
userinfo_endpoint | Array         | Yes
owned_resources   | Object        | Yes
allowed_resources | Object        | Yes
[sessions]        | Object        | Yes
credentials       | Array         | Yes

[sessions](#sessions-object)

**account_id**<br>
Login name of the account at the service, e.g., `rest@attacker.com`. CURRENTLY UNUSED

**user_id**<br>
Internal user ID at the service, e.g., `master-hacker-1234`. CURRENTLY UNUSED

**userinfo_endpoint**<br>
Contains an endpoint definition for testing the authorized communication with the API.
This can be used to check if the service has denied access to the client (because of rate/access limits or security protections).

The order of arguments is `[<server URL>, <endpoint path>, <endpoint operation>]`.

**owned_resources**<br>
Resources that are tied to the users account.

**allowed_resources**<br>
Resources that the user is allowed to access but does not own. CURRENTLY UNUSED

**sessions**<br>
Sessions for authenticated users that can be used to establish user agents for OAuth2 authorization
and token requests. They are defined as [session objects](#session-object). Keys are used as identifiers
for referencing the specific session object.

**credentials**<br>
Credentials that should be used for authorizing the user. CURRENTLY UNUSED


### `schemes` Object

Parameter | Type   | Optional
----------|--------|----------
type      | String | No
key_id    | String | No
payload   | String | No
params    | Object | No

**type**<br>
Type of the scheme that also determines the location of the created payload in the request.

The following types are supported by the tool:

- `header`: Creates a HTTP header payload
- `query`: Creates a query parameter key-value pair
- `cookie`: Creates a HTTP cookie key-value pair
- `basic`: Creates a HTTP Basic Authentication payload

**key_id**<br>
The string used for the key of the created key-value pair for the types `query` and `cookie`. If the type is
`header`, this value is used as the header name. If the type is `basic`, this value is ignored as its assumed
to use the *Authorization* header.

**payload**<br>
Pattern of the payload to create the value of the key-value pair for `query` and `cookie`, or the header payload
for type `header`, respectively. For type `basic`, the payload is inserted into the Base64-encoded part of the
header payload.

The mattern may contain parameters for dynamic auth data that is inserted at runtime, e.g. an access token value.
Parameters are referenced as IDs enclosed by curly braces (`{}`). The credentials used for this dynamic auth data
must be referenced in the `params` attribute.

**params**<br>
Defines the source of the auth data for parameters used in the pattern defined by the `payload` attribute. Keys
in the `params` object are parameter IDs. Each value is a parameter object that contains the following attributes.

Parameter | Type          | Optional
----------|---------------|----------
id        | String        | No
from      | Array[String] | No

The **from** attribute is a list of credentials IDs that can be used as a source for the auth value. The value of
**id** is the name of the key in the credentials object that is used to access the auth value.

---

Example (`header`):

```json
{
    "type": "header",
    "key_id": "authorization",
    "payload": "token {0}",
    "params": {
        "0": {
            "id": "access_token",
            "from": [
                "token0",
            ]
        }
    }
}
```

Assuming the access token for credentials `token0` is `12341234abab`, this scheme will result in the following header payload:

```
authorization: token 12341234abab
```

Example (`basic`):

```json
{
    "type": "basic",
    "key_id": "authorization",
    "payload": "{0}",
    "params": {
        "0": {
            "id": "access_token",
            "from": [
                "token0",
            ]
        }
    }
}
```

Assuming the access token for credentials `token0` is `12341234abab`, this scheme will result in the following header payload:

```
authorization: Basic MTIzNDEyMzRhYmFi
```


### `session` Object

Parameter       | Type   | Optional
----------------|--------|----------
type            | String | No
test_url        | String | Yes
*type-specific* | Any    | -

**type**<br>
Type of the session that also determines how the session is established.

**test_url**<br>
URL to a protected resource that only the owner of the session should be able to access.
After establishing the session, the tool will send a request to the URL. If the response
status is not a 2XX status code, the session is not considered valid.

The following types are currently supported:

- `[weblogin](#weblogin-type)`: Login via POST request to a login endpoint to create a new session
- `[cookie](#cookie-type)`: Use an established user session from cookies
- `[browser](#browser-type)`: (**Recommended**) Use an established user session in a browser


#### `weblogin` Type

Parameter | Type    | Optional
----------|---------|----------
url       | String  | No
params    | Object  | No

**url**<br>
Login endpoint URL.

**params**<br>
Key-value pairs of parameters sent in the HTTP body to the URL.


#### `cookie` Type

Parameter | Type    | Optional
----------|---------|----------
params    | Object  | No

**params**<br>
Key-value pairs of cookies copied from the established session.


#### `browser` Type

Parameter  | Type    | Optional
-----------|---------|----------
exec_path  | String  | No
local_port | String  | No

**exec_path**<br>
Path to the browser executable. Firefox or Chrome should both work, other browsers are untested.

**local_port**<br>
Port used for the tool's internal HTTP server. The port should be available when starting the tool.
