"""SentinelLoop: a self-hardening prompt-injection firewall with a red-team fuzzer.

Package layout:

* ``target_app``  - the deliberately vulnerable sandbox assistant and the judge
* ``firewall``    - defense layers, the OpenAI-compatible gateway and dashboard
* ``fuzzer``      - attack corpus, mutation operators, genetic / MAP-Elites search
* ``hardening``   - the closed loop that retrains the firewall on new bypasses
* ``evaluation``  - benchmark splits and report scripts
* ``sentinelloop``- shared harness, corpus loader and the command-line interface
"""

__version__ = "0.2.0"
