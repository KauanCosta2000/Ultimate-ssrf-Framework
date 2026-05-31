\# Architecture



Ultimate SSRF Framework is organized around a few core areas:



1\. Target handling

2\. Endpoint discovery

3\. SSRF testing modules

4\. Callback/OAST payload generation

5\. WAF fingerprinting

6\. Reporting and exports



The current public version keeps most of the logic in a single Python entrypoint for easier testing and distribution.



The next refactor will move the main components into a proper Python package structure.

