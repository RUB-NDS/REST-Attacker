# Advanced Usage

1. [Using REST-Attacker as a Module](#using-rest-attacker-as-a-module)
    1. [Loading Configuration](#loading-configuration)
    1. [Check Generation](#check-generation)
    1. [Initializing the Test Engine](#initializing-the-test-engine)
    1. [Controlling the Run](#controlling-the-run)
1. [Creating a Custom Test Case](#creating-a-custom-test-case)
    1. [Test Case Interface](#test-case-interface)
    1. [Sending Requests to the API](#sending-requests-to-the-api)
    1. [Getting Access Control Information](#getting-access-control-information)


## Using REST-Attacker as a Module

Choosing to use REST-Attacker as a module can give you much more control over
the check generation, testing, and reporting processes. Furthermore, it allows you to
write your own test cases for security or analysis checks.


### Loading Configuration

REST-Attacker provides parsers for every input configuration format in the
`rest_attacker.util.parsers` module.

1. [Auth files](/doc/formats/auth.md): `rest_attacker.util.parsers.config_auth`
1. [Info files](/doc/formats/info.md): `rest_attacker.util.parsers.config_info`
1. [Run files](/doc/formats/run.md): `rest_attacker.util.parsers.config_run`
1. OpenAPI: `rest_attacker.util.parsers.openapi`

These parsers automatically create configuration objects that the test engine needs.
If you don't want to use REST-Attacker's configuration formats, you need to
create the objects yourself. Check generation and starting a test run requires
at least an `EngineConfig` object which references all other configuration data.


### Check Generation

REST-Attacker's internal check generation is implemented in the `rest_attacker.engine.generate_checks`
module. The `generate_checks(..)` methods receives an `EngineConfig` object, a dict
of test cases mapped to their test case ID, and optional filters. You can pass
your own implemented test cases here if they inherit from the `TestCase` base class
([see here for implementing your own test cases](#test-case-interface)).

`generate_checks(..)` filters the provided test cases (if filters are defined) and then
calls their respective `generate(..)` methods to create checks. The list of generated
checks is returned in the end.


### Initializing the Test Engine

![Engine](images/engine.svg)

REST-Attacker executes a test run via the implemented `Engine` class that
you find in the `rest_attacker.engine.engine` module. It requires an
`EngineConfig` and a list of checks for intialization.

On initialization, the test engine will set up its statistics and internal
state tracking (`InternalState`) which you can access with the `state` member.
`InternalState` also manages trackers for rate limiting.


### Controlling the Run

The easiest way to start the test run is to call the `run()` method. This
starts an automated test run that iterates through all checks you provided and
manages the complete execution and internal updates.

If you want more fine-grained control, you can also access the methods used in each
iteration directly.

- `current_check(..)`: Executes the check at the current index (`index` member of `Engine`). The index is not automatically incremented by the method. You need to update the engine's `index` member manually.
- `update_handlers(..)`: Updates rate limit detection and checks if rate limits are reached.
- `status(..)`: Prints the current index and the total number of check to `stdout`.

After the test run is finished, you can write the results to a [report file](/doc/formats/report.md)
using the `export(..)` method. You may also access the individual reports for each check object
by accessing their `report(..)` method.


## Creating a Custom Test Case

Writing a custom test case allows you to execute your own security and analysis
checks with REST-Attacker. Test cases are all classes inheriting from the generic
`TestCase` interface in the `rest_attacker.checks.generic` module. The interface
describes the required methods that you need to implement which we will now explain in
detail.


### Test Case Interface

![Test Case Interface](images/test_case_interface.svg)

**`__init__(..)`**<br>
Initializes a check object for the test case. All parameters needed for test execution
should be passed to this method. The only mandatory member you need to define
is `self.check_id`.

It is recommended to call `super().__init__(..)` at the start of your initialization.
This automatically creates a `TestResult` object which can be used to store the results
of the test execution. You can access the member via `self.result`.

**`run()`**<br>
Implements the security tests for the test case. It is called by the test engine during the execution of its
`current_check(..)` method.

For communication with the API, you should use REST-Attacker's integrated [request backend](#sending-requests-to-the-api)
and [auth backend](#getting-access-control-information). However, you are free
to implement any tests you want in `run()`. The method has no restrictions on what
can or cannot be analyzed.

We recommend you use the `TestResult` object referenced by `self.result` to store
results of your tests and track the status of the test execution, although this
is not required. With `TestResult` a result summary can be easily exported using
its `dump()` method. The test engine also uses the `TestResult` object of a check
to update its internal statistics.

**`report(..)`**<br>
Creates an exportable report for the check. The method must return a `Report` object
that contains a JSON-compatible dict (i.e. it can be printed as a JSON object).

The easiest way to create a basic report is to call `dump(..)` of the `TestResult`
object and pass the result to a `Report` object. You can choose to add other values
in your report if you want.

**`generate(..)`**<br>
Implements load-time check generation for the test case. This method is called when
you pass the `--generate` flag to the CLI to automatically create a test run.

`generate(..)` can use any values in the API configuration provided by an `EngineConfig`
object for its generation. It must return a list of checks initialized from any
`TestCase` class. However, we recommend that you only generate checks for the same
`TestCase` class that implements the `generate(..)` method to avoid interdependencies.

If you don't want to enable automated load-time generation for the test case, return an empty list.

**`propose(..)`**<br>
Implements run-time check generation for the test case. This method is called by the
test engine after a check has been executed if you pass the `--propose` flag to the CLI.

`propose(..)` can use any values in the API configuration **and** any parameters of
the check object (for exampole the `TestResult`) for its generation. It must return
a list of checks initialized from any `TestCase` class.

If you don't want to enable automated run-time generation for the test case, return an empty list.

**`serialize(..)`**<br>
Saves the initialization parameters of a check to a JSON-compatible dict. This
method may be used to export the configuration of a check, so that it can be
reproduced later.

**`deserialize(..)`**<br>
Creates a check from a serialized configuration.


### Sending Requests to the API

![Request Backend](images/request_info.svg)

You can prepare and send request with REST-Attacker's `RequestInfo` class in
the `rest_attacker.util.request.request_info` module. `RequestInfo` allows you
to specify an API request consisting of

- API operation (HTTP method)
- API base URL
- Resource path

`RequestInfo` wraps around Python's `requests` HTTP library. Therefore, it accepts
all additional parameters that are also supported by `requests.Request`.

To make an API request, call the `send(..)` method of your initialized `RequestInfo`
object. The method will prepare the corresponding HTTP request and send it
via the `requests.request(..)` method. The received `requests.Response` is
returned.

`send(..)` allows you to pass access control payloads separately from other request
parameters. This is useful if you want to make the same API request with different
access levels or authentication methods, e.g., to compare how the API responds.
The method expects access control payloads generated by REST-Attacker's auth backend.


### Getting Access Control Information

![Auth Backend](images/auth_backend.svg)

Access control payloads for authorized API requests can be created via REST-Attacker's
auth backend. When starting via CLI, the backend is initialized from an [auth config](/doc/formats/auth.md)
referenced by the info file in the passed config directory. The auth backend gives
you several options for assembling access control payloads from automated generation
of payloads to more fine-rained control over the used schemes, credentials, and access
levels.

![Auth Generator](images/auth_gen.svg)

The simplest method to get an access control payload is using the `AuthGenerator` object
that can be accessed via the `auth` member of the test engine's `EngineConfig`. `AuthGenerator`
provides the method `get_auth(..)` which will automatically try to assemble a valid
access contol payload using the requirements in the auth config. `get_auth(..)`
optionally allows you to define the desired access level of OAuth2 credentials via
the `scopes` parameter.

You can also generate access control payloads for specific authentication schemes. To do
this, you can either pass a list of scheme IDs to `get_auth(..)` or requests a payload
for a specific scheme via the auth generators `get_auth_scheme(..)` method. `get_auth_scheme(..)`
also allows you to manually pass credential information that should be used for the payload
via the `credentials_map` parameter.

![Token Generator](images/token_generator.svg)

Credentials from the auth config are stored in the `credentials` member of the test
engine's `EngineConfig`. Credentials are referenced by their ID in the auth config.
Plaintext credentials like passwords and API keys can be accessed directly,
while dynamic credentials such as OAuth2 tokens have to be requested from the API.
For this purpose, REST-Attacker provides the `OAuth2TokenGenerator` class which
is initialized for every OAuth2 client defined in the auth config. `OAuth2TokenGenerator`
supports OAuth2's authorization code, implicit, and refresh flows and can
handle token retrieval in the background if user session information is
defined in the auth config.
