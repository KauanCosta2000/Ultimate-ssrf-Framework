\# Examples



\## Basic Scan



```bash

python ssrf\_arsenal.py --target example.com

```



\## Target File



```bash

python ssrf\_arsenal.py --target-file targets.txt

```



\## Burp Collaborator



```bash

python ssrf\_arsenal.py \\

\--target example.com \\

\--burp-collaborator abc.burpcollaborator.net

```



\## Full Export



```bash

python ssrf\_arsenal.py \\

\--target example.com \\

\--output reports \\

\--export-nuclei \\

\--export-siem \\

\--export-json-api \\

\--attack-map

```

