# Reports

Reports contain the results of checks in a test run. They also contain other helpful
information about the run such as statistics and test configuration parameters to
replicate the run.

For every test run, a report and a logfile is created. Files are saved to the directory
specified with the `--output-dir` flag, or `rest-attacker/out/` if no output directory
was specified.


## Test Results in the Report

A report is stored as a JSON file (`report.json`). The complete format is documented
[here](doc/formats/report.md). In this document, we will briefly cover the most
relevant parts of the report format.

You can see if your test run was completed successfully by checking the value of the `type`
attribute. If the type is `report`, all checks were completed. If the type is `partial`,
then the run was aborted at some point. This can happen if the tool detects that it
reached an unrecoverable rate/access limit or if the test run was manually aborted
via a `KeyboardInterrupt`. Aborted runs can be continued by using them as a run
configuration:

```
python3 -m rest_attacker <config-path> --continue report.json
```

`stats` displays you statistics of the run, e.g. start and end times of the test run as
well as the number of completed checks.

If you started the test run via command-line, the arguments passed to the CLI are
listed in the `args` attribute.

Results for the individual checks can be found in the `reports` array. Every check
gets its own report. A simple summary of the detected can be seen in the `issue`
attribute of the check report. Its value tells you if the tool found a security issue
or behaviour that should be analyzed. The `value` attribute contains more information
that helps you interpret the issue result.


## Reproducing a Run from a Report File

Reports can be used to reproduce a run if the check configuration parameters
are stored in the individual check reports (this should be active by default).
To do so, simply use report file as run configuration:

```
python3 -m rest_attacker <config-path> --run report.json
```

The service config should not be altered significantly between runs as the
configuration parameters only reference IDs of API descriptions, authentication
schemes, and credentials and not the used values themselves. Beware that any
authorization data for the initial test run, such as OAuth2 tokens, are not reused
in the reproduced run. Instead, they are requested again from the service.
