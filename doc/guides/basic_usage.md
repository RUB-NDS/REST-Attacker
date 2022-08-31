# Basic Usage

1. [Setup](#setup)
1. [First Start](#first-start)
1. [Viewing Results of a Test Run](#viewing-results-of-a-test-run)
1. [Configuring More API Parameters](#configuring-more-api-parameters)
1. [Automated Access Control](#automated-access-control)
1. [Automated Rate Limit Detection](#automated-rate-limit-detection)

## Setup

Running REST-Attacker requires at minimum:

* **OpenAPI file** (version 2.0+) that describes the API you want to analyze

Optionally, you may additionally configure:

* **[Info file](/doc/formats/auth.md)** for extended API configuration
    * Multiple API descriptions
    * Miscellaneous API configuration parameters (if not available in API description)
        * Content types
        * OAuth2 scopes
    * Custom headers for rate limiting
* **[Auth file](/doc/formats/auth.md)** for automated handling of authentication/authorization with the tool
    * Authentication/Authorization schemes
    * Required access control methods
    * Credentials for user account(s) at the service
    * Credentials for OAuth2 client(s) at the service

## First Start

Starting a test run requires the setup configuration and a run configuration containing
checks and their parameters. REST-Attacker can also generate the run configuration for you
if you pass it the `--generate` flag:

```
python3 -m rest_attacker <openapi-file> --generate
```

With this option, REST-Attacker will try to automatically generate checks for all
built-in test cases using the given OpenAPI file. REST-Attackers test cases cover a variety of different
analysis and security issues. The code for the implemented test cases is available in the
`checks` submodule.

You can also see the list of test cases by running:

```
python3 -m rest_attacker --list
```

If you only want to generate checks for specific test cases, you can pass a list of test case IDs to the
`--test-cases` argument:

```
python3 -m rest_attacker <openapi-file> --generate --test-cases scopes.TestTokenRequestScopeOmit resources.FindSecurityParameters
```

For example, this command would only generate a test run with checks for the
`scopes.TestTokenRequestScopeOmit` and `resources.FindSecurityParameters` test cases.

Check generation can be enhanced with run-time generation using the `--propose` flag.
This option will generate checks during a test run using test results from test execution.
`--propose` and `--generate` can also be combined:

```
python3 -m rest_attacker <openapi-file> --generate --propose
```

Currently, `--propose` only works for a few of the built-in checks, so you may not see any
run-time generated checks if you filter for certain test cases.


## Viewing Results of a Test Run

Results of a test run are exported to the directory `rest_attacker/out` by default.
Alternatively, you can specify the report folder with the `--output-dir` argument:

```
python3 -m rest_attacker <openapi-file> --generate --output-dir /tmp/example_run/
```

For more information on report files, see the [report docs](/doc/guides/report.md).


## Configuring More API Parameters

Some of the more advanced features require further configuration in addition to the OpenAPI description,
namely the automated handling of access control and rate limit detection. You can find
templates for all configuration formats in the [formats documentation directory](/doc/formats/).
If this is your first time using the configuration formats, the easiest way to start is
to create a copy of the "Quickstart" templates for each format that is mentioned here and fill
in the respective config values for the API you want to test.

Configuration files must be stored in a directory that you pass to the tool as the config.
A file called `info.json` ([format documentation](/doc/formats/info.md)) needs to be present
in this directory. It contains references to other config files and is the only
required config file.

`info.json` must specify at least one OpenAPI file in its `descriptions` attribute. You may
add alternative OpenAPI descriptions for the service. However, only the first available
OpenAPI description is used for the automated check generation with the `--generate` flag
by default.

Starting the tool with a custom configuration looks like this:

```
python3 -m rest_attacker <config-path> --generate --output-dir
```

As config path you can either pass

1. A relative or absolute directory *path* on your system
2. The *name* of a directory inside the `rest_attacker/cfg/` subfolder


### Automated Access Control

If the API you want to test has protected endpoints or requires the usage of access control
mechanisms, you can supply an *auth config* to REST-Attacker to automate the necessary
access control flows. REST-Attacker is able to handle many authentication and authorization
processes in the background, without requiring manual intervention. This includes building
authorized API requests, retrieval of OAuth2 access tokens, and determining the
correct access levels to use for the respective endpoints. Some built-in
test cases also require an existing auth config for their automated check generation.

The auth config for the API is placed in an auth file (usually called `auth.json` or 
`credentials.json`) ([format documentation](/doc/formats/info.md)). The path to this file
**must be referenced in the mandatory `info.json` file**.

The auth config allows you to configure:

- Credentials
    - Static (e.g. username/password, token values)
    - Dynamic (e.g. OAuth2 clients)
- Authentication/Authorization schemes for the API request
- API requirements for schemes
- User sessions

### Automated Rate Limit Detection

REST-Attacker can check and detect whether the API has blocked requests of the tool during
the test execution process duze to rate limits. It can currently check for two types of rate limits:

1. Standard rate limits limiting the general number of API requests
2. Generic access limits that block access to the API (these can be caused by multiple factors, e.g. sending
too many requests to the same endpoint)

You can activate rate limit detection by passing the `--handle-limits` flag to
the CLI call:

```
python3 -m rest_attacker <config-path> --generate --handle-limits
```

By default, this can only detect if a standard rate limit has been reached by looking for
HTTP status code `429` in API responses. However, you can enhance the naive rate limit detection
by supplying additional configuration.

Some APIs may return headers in their API responses that communicate the remaining
rate limit. REST-Attacker can utilize these headers to avoid triggering a rate limit
and to pause a test run in case it needs to. Rate limit headers can be configured
in the `custom_headers` attribute of the info file.

To detect generic access limits, you need to configure at least one user in the auth config
with the `userinfo_endpoint` attribute. This endpoint must be accessible to the configured
user and must return a `2XX` status code in return to an authorized API request. During a test
run, REST-Attacker will send regular API requests to this endpoint to check if it can
still access the endpoint. If the API response no longer contains a `2XX` response code,
REST-Attacker will assume an access limit has been reached an will terminate the test run.