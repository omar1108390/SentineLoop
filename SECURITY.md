# Security and responsible use

SentinelLoop is a research prototype for prompt-injection testing. Its built-in target uses synthetic messages, files, and calendar entries. The fake tools do not send email, access user files, or contact external services.

Run the fuzzer only against the built-in sandbox or systems you own or have explicit permission to assess. Do not use the attack corpus or mutation tools against third-party services without authorization.

The gateway can forward prompts to an upstream model when `SENTINELLOOP_UPSTREAM_URL` is configured. Those prompts leave the local machine and are subject to that provider's retention and privacy terms. Keep credentials in environment variables and do not use real personal or confidential data in this prototype.

Model-generated tool calls are currently withheld from clients; there is no live tool executor. Keep the fake target isolated and do not connect it to real email, files, calendars, or accounts.

For a security issue in SentinelLoop, share a minimal reproduction privately with the project maintainers before public disclosure.
