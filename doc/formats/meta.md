# Metafile

The meta file stores descriptions and meta information about a service. All information is stored in JSON format.
It can be used to categorize a service if multiple services are tested. Meta files are currenty not used during
testing, although they may be used for debug output in the future.

The meta file is referenced in the mandatory [info file](info.md). The preferred filename is `meta.json`.

## Quick Reference

```json
{
    "name": "MyService",
    "description": "An example service",
    "tags": [
        "misc",
        "example"
    ],
    "docs": "https://example.com/docs/restapi/"
}
```

## Attributes

Parameter   | Type          | Optional
------------|---------------|---------
name        | String        | No
description | String        | No
tags        | Array[String] | No
docs        | String        | No

**name**<br>
Human-readable name of the service or name of the API.

**description**<br>
Human-readable description of the service or API.

**tags**<br>
An array of strings that act as tags to categorize the service. Tags can be chosen arbitrarily by users.

**docs**<br>
URL that links to the documentation for the service or API.
