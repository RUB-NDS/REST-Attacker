# Reportfile

The report file contains the results of an executed test run as well as statistics
and meta information about the analyzed API.

Report files can also be used as run configurations to replicate a run if check
parameters were exported alongside the check results.

The default filename is `report.json`.


## Quick Reference

```json
{
    "type": "report",
    "meta": {
        "name": "MyService",
        "description": "An example service"
    },
    "stats": {
        "start": "2022-07-16T14-27-20Z",
        "end": "2022-07-16T14-27-25Z",
        "planned": 1,
        "finished": 1,
        "skipped": 0,
        "aborted": 0,
        "errors": 0,
        "analytical_checks": 0,
        "security_checks": 1
    },
    "args": [
        "example.json",
        "--generate"
    ],
    "reports": [
        {
            "check_id": 0,
            "test_type": "security",
            "test_case": "https.TestHTTPAvailable",
            "status": "finished",
            "issue": "security_flaw",
            "value": {
                "status_code": 200
            },
            "curl": "curl -X GET http://api.example.com/user",
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

Parameter      | Type          | Optional
---------------|---------------|----------
type           | String        | No
meta           | Object        | Yes
[stats]        | Object        | Yes
args           | Array[String] | Yes
[reports]      | Array[Object] | No

[stats](#stats-object)
[reports](#reports-object)

**type**<br>
Report type. Can be either `report` for a completed run (every check executed) or
`partial` for a run that was aborted before completion.

**meta**<br>
Meta information of the service. Contains the content of the [meta file](meta.md) if
it is configured.

**stats**<br>
Statistics about the test run ([see here for more details](#stats-object)).

**args**<br>
Command-line arguments passed at the start of the test run if the run was initiated
via CLI.

**reports**<br>
Reports for the individual checks ([see here for more details](#reports-object)).


## `stats` Object

Statistcs about the test run.

Parameter         | Type          | Optional
------------------|---------------|----------
start             | String        | No
end               | String        | No
planned           | Number        | No
finished          | Number        | No
skipped           | Number        | No
aborted           | Number        | No
errors            | Number        | No
analytical_checks | Number        | No
security_checks   | Number        | No

**start**<br>
Start date and time of the test run.

**end**<br>
End date and time of the test run.

**planned**<br>
Number of checks that were planned for the test run (i.e. the number of checks
passed to the engine during initialization).

**finished**<br>
Number of checks that were completed sucessfully (without being skipped or
generating uncaught exceptions).

**skipped**<br>
Number of checks skipped during the test run.

**aborted**<br>
Number of aborted checks when terminating the test run early.

**errors**<br>
Number of checks that failed because of unexpected errors.

**analytical_checks**<br>
Number of *planned* analysis checks.

**security_checks**<br>
Number of *planned* security checks.


## `report` Object

Report for an individual check.

Parameter  | Type        | Optional
-----------|-------------|----------
report_id  | Number      | No
check_id   | Number      | No
test_type  | String      | No
test_case  | String      | No
status     | String      | No
issue      | String      | No
value      | Object      | No
curl       | String      | Yes
config     | Object      | Yes

**report_id**<br>
Reference ID for this report.

**check_id**<br>
Reference ID of the check the report belongs to.

**test_type**<br>
Type of test case that was executed. Can be one of these values:

Value     | Description
----------|------------
security  | Checks for security issues or flaws.
analysis  | Analyzes behaviour or configiration of the API.

**test_case**<br>
ID of the test case of the check.

**status**<br>
Status of the check after execution. Can be one of these values.

Value     | Description
----------|------------
finished  | Check completed without unexpected errors.
skipped   | Check was skipped.
error     | Check failed with an unexpected error.
aborted   | Check was aborted because the test run was terminated.

**issue**<br>
Simple classification of the detected issue. The possible value are different depending
on the test type.

For the security test type, these values are possible:

Value             | Description
------------------|------------
security_okay     | No security issue has been found.
security_problem  | Indicators for a security issue have been found, but a flaw could not be confirmed.
security_flaw     | A security issue was found and could be confirmed.

For the analysis test type, these values are possible:

Value              | Description
-------------------|------------
analysis_candidate | The check detected the behaviour/configuration it was looking for.
analysis_none      | The check did not find the behaviour/configuration it was looking for.

**value**<br>
Additional parameters for interpreting the check result. The format of this object
depends on the test case.

**curl**<br>
Curl command for replicating an API request sent by the check.

**config**<br>
Serialized configuration of the check. If present, the check can be replicated
when the report file is passed to the tool as a run configuration. The format of this object
depends on the test case.