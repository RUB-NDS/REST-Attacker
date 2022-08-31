# Troubleshooting

## "Mismatching state"/"CSRF Warning!" error during token generation

This can happen if the Chrome browser is used for handling user sessions. Chrome sometimes calls the redirect URI in OAuth2 authorization flows twice. However, the current implementation can only handle one request at the time. Thus, the next authorization flow will handle the second (outdated) Chrome request first.

If this happens, you should restart the run.


## "Rate Limit reached" / "Access Limit reached. Aborting Run" message

In this case, the tool has detected that it cannot access the API anymore. This usually happens if too many authorization requests are sent to the authorization server or too many unauthorized requests to the API.

If this happens, wait for a while and continue the test run by providing the report of the aborted run as a run configuration. This will continue the run.
Alternatively, you can omit the `--handle-limits` flag in the CLI commands. Then, the rate/access limit detection is deactivated.


## Test case execution stops / "Rate Limit reached" message

In this case, the tool has detected that a rate limit has been exceeded. The run is halted until the rate limit resets (this may be detected from a response header).
The run will continue after the rate limit has been reset. Alternatively, you can abort the run with `CTRL + C` and view the report for the already executed checks. You can continue the run by supplying the report file as a run configuration.


## Firefox/Chrome does not open even though browser session is defined in service configuration

`ROBrowserSession` currently does not work inside a Docker container. Open the repository outside of the Docker container and restart the test run.
