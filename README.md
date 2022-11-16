# REST-Attacker

REST-Attacker is an automated penetration testing framework for APIs following the REST architecture style.
The tool's focus is on streamlining the analysis of generic REST API implementations by completely automating
the testing process - including test generation, access control handling, and report generation - with minimal
configuration effort. Additionally, REST-Attacker is designed to be flexible and extensible with support
for both large-scale testing and fine-grained analysis.

REST-Attacker is maintained by the [Chair of Network & Data Security](https://informatik.rub.de/nds/) of the Ruhr University of Bochum.


## Features

REST-Attacker currently provides these features:

- **Automated generation of tests**
    - Utilize an OpenAPI description to automatically generate test runs
    - 32 integrated security tests based on [OWASP](https://owasp.org/www-project-api-security/) and other scientific contributions
    - Built-in creation of security reports
- **Streamlined API communication**
    - Custom request interface for the REST security use case (based on the Python3 [requests](https://requests.readthedocs.io/en/latest/) module)
    - Communicate with any generic REST API
- **Handling of access control**
    - Background authentication/authorization with API
    - Support for the most popular access control mechanisms: OAuth2, HTTP Basic Auth, API keys and more
- **Easy to use & extend**
    - Usable as standalone (CLI) tool or as a module
    - Adapt test runs to specific APIs with extensive configuration options
    - Create custom test cases or access control schemes with the tool's interfaces


## Install

Get the tool by downloading or cloning the repository:

```
git clone https://github.com/RUB-NDS/REST-Attacker.git
```

You need Python >3.10 for running the tool.

You also need to install the following packages with pip:

```
python3 -m pip install -r requirements.txt
```

## Quickstart

Here you can find a quick rundown of the most common and useful commands. You can find more
information on each command and other about available configuration options in our [usage guides](doc/usage).

Get the list of supported test cases:

```
python3 -m rest_attacker --list
```

Basic test run (with load-time test case generation):

```
python3 -m rest_attacker <cfg-dir-or-openapi-file> --generate
```

Full test run (with load-time and runtime test case generation + rate limit handling):

```
python3 -m rest_attacker <cfg-dir-or-openapi-file> --generate --propose --handle-limits
```

Test run with only selected test cases (only generates test cases for test cases `scopes.TestTokenRequestScopeOmit` and `resources.FindSecurityParameters`):

```
python3 -m rest_attacker <cfg-dir-or-openapi-file> --generate --test-cases scopes.TestTokenRequestScopeOmit resources.FindSecurityParameters
```

Rerun a test run from a report:

```
python3 -m rest_attacker <cfg-dir-or-openapi-file> --run /path/to/report.json
```


## Documentation

Usage guides and configuration format documentation can be found in the [documentation](/doc) subfolders.


## Troubleshooting

For fixes/mitigations for known problems with the tool, see the [troubleshooting docs](/doc/troubleshooting.md) or the [Issues](https://github.com/RUB-NDS/REST-Attacker/issues) section.


## Contributing

Contributions of all kinds are appreciated! If you found a bug or want to make a suggestion or feature request, feel free
to create a new [issue](https://github.com/RUB-NDS/REST-Attacker/issues) in the issue tracker. You can also submit fixes
or code ammendments via a [pull request](https://github.com/RUB-NDS/REST-Attacker/pulls).

Unfortunately, we can be very busy sometimes, so it may take a while before we respond to comments in this repository.


## License

This project is licensed under **GNU LGPLv3 or later** (LGPL3+). See [COPYING](/COPYING) for the full license text and
[CONTRIBUTORS.md](/CONTRIBUTORS.md) for the list of authors.





