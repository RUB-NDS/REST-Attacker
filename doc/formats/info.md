# Infofile

The info file stores a service configuration that is used to initialize the checks in REST Attacker.
For this reason, the info file is mandatory when testing a service.

The filename must be `info.json`.

## Quick Reference

```json
{
    "descriptions": {
        "openapi0": {
            "available": true,
            "date": "2021-09-04",
            "path": "openapi.json",
            "alt_versions": [],
            "format": "openapi",
            "official": false
        }
    },
    "meta": "meta.json",
    "credentials": "credentials.json",
    "auth_methods": [
        "oauth2"
    ],
    "scopes": [
        "user",
        "admin"
    ],
    "content_types": [
        "application/json"
    ],
    "custom_headers": {
        "rate_limit_max": "RateLimit-Limit",
        "rate_limit_remaining": "RateLimit-Remaining"
    }
}
```

## Attributes

Parameter      | Type          | Optional
---------------|---------------|----------
[descriptions] | Object        | Yes
meta           | String        | Yes
credentials    | String        | Yes
scopes         | Array[String] | Yes
content_types  | Array[String] | Yes
custom_headers | Object        | Yes

[descriptions](#descriptions-object)

**descriptions**<br>
API descriptions for the service ([see here for more details](#descriptions-object)). Keys
are used as identifiers for referencing the specific API description.

**meta**<br>
Path to the [meta file](meta.md) of the service.

**credentials**<br>
Path to the [credentials file](credentials.md) of the service. If no credentials file is referenced,
REST Attacker will only execute unauthenticated/unauthorized checks.

**scopes**<br>
Scopes supported by the service.

**content_types**<br>
Content types supported by the service.

**custom_headers**<br>
Maps handler types to response header IDs which are tracked by the tool during the analysis.
After every check, the last response received by the tool is returned and can be analyzed by
a `ResponseHandler`. Currently, this is only used for tracking rate limits, but it may be used
for tracking other types of information.

The built-in handler types can be referenced with these keys:

Key                  | Handler Type | Description
---------------------|--------------|------------
rate_limit_max       | Rate limit   | Maximum rate limit (per intervall)
rate_limit_remaining | Rate limit   | Remaining rate limit (in intervall)
rate_limit_reset     | Rate limit   | Reset time of rate limit


## `descriptions` Object

Defines an API description of the service's API.

Parameter      | Type          | Optional
---------------|---------------|----------
path           | String        | No
available      | Boolean       | No
official       | Boolean       | Yes
date           | String        | Yes
alt_versions   | Array[String] | Yes
format         | String        | Yes

**path**<br>
Relative path to the description file.

**available**<br>
Signifies whether the analysis tool is allowed to use this API description. If `false`, the description
is not loaded.

**official**<br>
Signifies whether this file is from an official source (i.e. the service's documentation) or created
externally by other parties.

This attribute is currently purely informational and has not influence on the analysis. It may be used
in the future to compare official and unofficial descriptions of the same API.

**date**<br>
The date the API description was created (if known). Expects ISO 8601 format.

Currently this attribute is not used. REST Attacker may use the `date` attribute in the future to compare
different versions of the same API.

**alt_versions**<br>
IDs of alternative versions of the API description, i.e. versions that use a different file format (e.g. YAML)
or API description format (e.g. RAML).

Currently this attribute is not used. REST Attacker may use the `alt_versions` attribute in the future to compare
differences in API descriptions for the same API version.

**format**<br>
The description format used for the file referenced in `path`. The only supported value is `openapi`. If this
attribute is missing, REST attacker will use `openapi` by default.

