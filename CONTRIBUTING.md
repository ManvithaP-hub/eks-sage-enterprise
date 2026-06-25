# Contributing to EKS Sage Enterprise

## Setup

```bash
git clone https://github.com/ManvithaP-hub/eks-sage-enterprise
cd eks-sage-enterprise
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
```

## Adding a New Tool

1. Implement logic in appropriate module under `src/eks_sage_enterprise/tools/`
2. Register in `server.py` with `@mcp.tool()` decorator
3. Add to `TOOL_CLASSIFICATIONS` in `core/guardrails.py`
4. Add unit test in `tests/`
5. Update README tool count and category table

## Adding to Denylist

Add to `NEVER_ALLOW` in `core/guardrails.py`.
Format: `"operation_name"` (lowercase).

## Code Style

- Type hints on all function signatures
- Docstring on every `@mcp.tool()` function
- Return `_j(dict)` — never return raw strings
- Handle all exceptions — never let tools crash the server

## Pull Request Guidelines

- One feature/fix per PR
- Tests required for new tools
- Update CHANGELOG.md
