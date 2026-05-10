Run full validation on the repository.

Execute `make validate` which runs yamllint and kustomize build for all environments.

If validation fails:
1. Parse the error output to identify the failing file(s) and line number(s)
2. Read the failing file(s) and diagnose the issue
3. Suggest specific fixes with code snippets
4. After the user approves fixes, re-run `make validate` to confirm

If validation passes, report success with a summary of what was checked (number of YAML files linted, number of overlay directories built).
