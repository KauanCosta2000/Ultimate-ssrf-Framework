\# Callback / OAST Usage



The framework supports OAST-compatible callback domains through:



```bash

\--callback

\--collaborator

\--burp-collaborator

```



Examples:



```bash

python ssrf\_arsenal.py --target example.com --callback abc.oastify.com



python ssrf\_arsenal.py --target example.com --burp-collaborator abc.burpcollaborator.net

```



The scanner generates unique callback payloads for SSRF validation.

