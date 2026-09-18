# LLM-SEC

Local defensive PII scanning and document inspection. This is an early-stage toolkit, not a production assurance system.

## Implemented baseline

- Regex detection for email addresses, SSN-shaped values, and a limited API-key pattern.
- Optional local spaCy NER for PERSON, ORG, and GPE entities. Entity matches are potential sensitive data, not confirmed leaks.
- Masked findings by default, bounded inputs (100,000 characters), and explicit stage coverage.
- Document text heuristics for configured instruction signatures, hidden characters, and repetition. These do not inspect vector databases or embeddings.
- A local stdio MCP tool, `scan_text_for_pii`, returning structured, masked results.
- A static Next.js dashboard prototype with no backend connection.

Semantic/reconstructed PII detection is **not implemented**. Reports always include `complete: false`; missing optional NER dependencies/models are reported as `unavailable`. No findings does not prove an absence of sensitive data. Document `is_safe` means only that no configured heuristic flagged the text; scores are not calibrated probabilities.

## Installation

Requires Python 3.11 or newer. The base CLI uses only the standard library.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m llmsec --help
```

Optional installations:

```bash
python -m pip install -e '.[mcp]'
python -m pip install -e '.[ner]'
python -m spacy download en_core_web_sm
```

The last command explicitly downloads a model. Scanning itself never downloads models or calls an external LLM API. Provision an approved local model before offline use. `requirements.txt` installs both runtime extras from `pyproject.toml`; dependency ranges are not a reproducible transitive lockfile.

## Commands

```bash
llmsec scan 'fixture@example.test' --regex-only --json
llmsec scan --file sample.txt --json
llmsec inspect-document 'ordinary local document' --json
llmsec health
```

`python -m llmsec` is equivalent to `llmsec`. Use files rather than shell arguments for sensitive input to avoid shell-history/process-list exposure. `--include-values` explicitly exposes raw PII in local CLI output; omit it for normal use. JSON output is plain JSON on stdout. Input/scan failures exit nonzero; findings themselves do not change the exit code. Health checks validate regex and document heuristics only, not NER availability or semantic coverage.

The supported CLI does not persist evidence. Legacy SQLite memory/redactor modules remain unsupported and are not used or included in the wheel. Existing evidence requires a separate access-control and retention policy.

## Local MCP

```bash
llmsec-mcp
```

Configure a trusted local MCP client to launch this command over stdio. There is no HTTP listener, port 8000 endpoint, remote authentication, or Redis service. Authorization rests on the OS permissions and trust of the client launching the process. Do not expose or bridge this process to untrusted remote callers. The legacy `mcp_server/security.py` decorators are not a deployed security boundary and are excluded from the distribution.

The tool masks values and serializes scanner execution. Its character limit is an application limit, not a transport-frame limit or hard CPU deadline. Thread cancellation does not forcibly terminate underlying model execution.

## Container

```bash
docker compose build
docker compose run --rm -T llmsec-mcp
```

Compose runs the stdio service without networking, as a non-root user, with a read-only filesystem and bounded temporary storage/resources. No ports, secrets, or evidence volumes are mounted. The default image does not contain spaCy or its NER model and reports degraded coverage. Docker alone does not inherit Compose hardening; use the Compose configuration. Image digests and transitive dependency locks remain release-hardening work.

## Development checks

```bash
python -m pip install -e '.[dev,mcp]'
python -m pytest tests/ -v
python -m ruff check .
python -m mypy
python -m build
```

Lint and type checking currently cover the supported defensive modules and their new tests, not every legacy experiment. The development extra includes LangGraph solely for the existing agency-auditor tests. Those tests exercise keyword/boolean heuristics, not authenticated approval enforcement. NER tests use local mocks rather than establishing accuracy of a real model.

For the dashboard, install dependencies with `npm ci`, then use `npm run dev` or `npm run build`. Its metrics and controls are demonstration-only.

## Scope and next milestones

- Establish an evaluated local semantic PII detector using synthetic labeled fixtures, measured precision/recall, and explicit uncertainty before making reconstructed-leakage claims.
- Define structured permission/approval evidence for defensive agency auditing.
- Add release locks, container build checks, and a securely connected dashboard only after a service trust model is defined.
- Vector database connectors, DeepEval/Giskard integration, OWASP-mapped evidence reports, and full-system campaigns are not implemented in the supported package.

Legacy campaign modules remain in the repository but are excluded from the installed wheel and CLI/MCP surface. Their simulations are not security results. Known malformed imports in `core/engine.py` and `core/injection.py` remain outside this defensive baseline. The former `art_t.py` CLI and import-time scaffolding generator have been retired in favor of `llmsec`.
