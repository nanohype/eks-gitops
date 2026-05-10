# Contributing

## Branch Naming

- `feat/<description>` — new addons or features
- `fix/<description>` — bug fixes
- `docs/<description>` — documentation changes
- `refactor/<description>` — restructuring without behavior change

## Commit Conventions

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add prometheus-operator addon
fix: correct loki retention period for production
docs: update environment configuration guide
refactor: normalize ApplicationSet generators
```

## Pull Request Checklist

- [ ] YAML lint passes: `make lint-yaml`
- [ ] All environments build: `make kustomize-build`
- [ ] Environment values files (`values-{env}.yaml`) contain only deltas (not full base copy)
- [ ] Sync wave number follows category ordering
- [ ] New Helm addons have all four values files (base + 3 environments)
- [ ] New Kustomize addons have base + 3 overlay directories
- [ ] ApplicationSet updated if addon list changed

## YAML Standards

- Use 2-space indentation
- No trailing whitespace
- Maximum line length: 200 characters
- Comments use `# ` (space after hash)
- Multi-line strings use `|` (literal block scalar)
- Quote strings that could be misinterpreted (`"true"`, `"3.14"`, `"0.0.0.0:4317"`)

## Environment Values Pattern

Environment values files (`values-{env}.yaml`) must contain only environment-specific differences:

```yaml
# Good — delta only
operator:
  replicas: 1

# Bad — full copy of base
operator:
  replicas: 1
  resources:
    requests:
      cpu: 100m      # same as base
      memory: 256Mi   # same as base
```

## Testing Changes Locally

```bash
# Render all addons for an environment
make render ENVIRONMENT=dev

# Compare rendered output between environments
diff <(make render ENVIRONMENT=dev 2>/dev/null) <(make render ENVIRONMENT=staging 2>/dev/null)

# Lint all YAML
make lint-yaml
```
