# Task 1 sample inputs

| File | What it is | Where it comes from |
|---|---|---|
| `log4shell.log` | Log4Shell attack log line, no CVE number | proposal section 4.3 (demo input 1) |
| `pip_audit.txt` | `pip-audit -r requirements.txt` table for `jinja2==2.10` | real pip-audit 2.10.1 output, Nov 2026 |
| `pip_audit.json` | same scan with `-f json` | real pip-audit 2.10.1 output, Nov 2026 |
| `jackson_note.txt` | messy note, needs the LLM fallback | proposal section 4.3 (backup example) |
| `requirements.txt`, `npm_note.txt`, `cve_only.txt`, `java_stacktrace.log` | small extra cases | written for the tests |

`pip_audit_dark.png` (demo input 2, a dark-mode screenshot of `pip_audit.txt`) is added in Prompt 3.
Do not edit the pip-audit files by hand; re-run pip-audit instead.
