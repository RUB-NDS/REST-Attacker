# Runfile

Run configuration file for creating a test run with specified checks.


## Quick Reference

```json
{
    "type": "run",
    "checks": [
        {
            "check_id": 0,
            "test_case": "https.TestHTTPAvailable",
            "config": {
                "request_info": {
                    "url": "http://api.example.com",
                    "path": "/user",
                    "operation": "get",
                    "kwargs": {
                        "allow_redirects": false
                    }
                },
                "auth_info": {
                    "scheme_ids": null,
                    "scopes": null,
                    "policy": "DEFAULT"
                }
            }
        }
    ]
}
```


## Attributes

Parameter   | Type          | Optional
------------|---------------|----------
type        | String        | No
[checks]    | Array[Object] | No

[checks](#checks-object)


**type**<br>
Run configuration type. Value must be `run`.

**checks**<br>
Configuration parameters for the individual checks ([see here for more details](#checks-object)).


## `checks` Object

Check definitions for the test run.

Parameter  | Type        | Optional
-----------|-------------|----------
check_id   | Number      | No
test_case  | String      | No
config     | Object      | Yes

**check_id**<br>
(Unique) reference ID of the check.

**test_case**<br>
ID of the test case of the check.

**config**<br>
Serialized configuration of the check. The format of this object depends on the test case.