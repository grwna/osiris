# CI evidence

Latest workflow run: https://github.com/grwna/osiris/actions/runs/43674601504
Full evidence of the run can be found under: [43674601504/](./43674601504/)

Extracted evidence for the run:

| Scenario | Evidence directory | Expected result | Evidence checked |
|---|---|---|---|
| C01 ECDSA P-256 | `43674601504/C01/ecdsa-p256-sha256/` | `OK`, exit 0 | `verification.json`; deployment marker present |
| C01 Ed25519 | `43674601504/C01/ed25519/` | `OK`, exit 0 | `verification.json`; deployment marker present |
| C01 RSA-PSS | `43674601504/C01/rsa-pss-sha256/` | `OK`, exit 0 | `verification.json`; deployment marker present |
| C02 tampered artifact | `43674601504/C02/` | `ARTIFACT_MISMATCH`, exit 1 | `verification.json`, `verify.stderr`; no deployment marker |
| C03 empty trust store | `43674601504/C03/` | `KEY_NOT_TRUSTED`, exit 1 | `verification.json`, `verify.stderr`, `trust.json`; no deployment marker |
| C04 missing artifact | `43674601504/C04/` | `INPUT_ERROR`, exit 2 | `verification.json`, `verify.stderr`; no deployment marker |
| C05 container constraints | `43674601504/C05/` and C01 run logs | success | Run the CLI with runner UID/GID and `--network none`, included in each C01 job |

The negative-case workflow checks assert the expected process exit code and marker absence before succeeding. 

## Download another run

With GitHub CLI authenticated for the repo, download and extract all artifacts
from a run into a new directory named by using the run ID:

Example:

```sh
tests/evidence/download-run.sh https://github.com/grwna/osiris/actions/runs/43674601504
```

Artifacts are grouped as `tests/evidence/<run-id>/C01/<algorithm>/` and `C02/` through `C05/`.
