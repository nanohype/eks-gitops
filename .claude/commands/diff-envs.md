Compare rendered manifests between two environments.

Ask the user which two environments to compare (from: dev, staging, production). Default to dev vs staging if not specified via $ARGUMENTS.

Steps:
1. Create temporary directories for each environment's rendered output
2. Render environment A: `make render ENVIRONMENT=<env-a>` then copy `rendered/` contents to temp dir A
3. Run `make clean`
4. Render environment B: `make render ENVIRONMENT=<env-b>` then copy `rendered/` contents to temp dir B
5. Run `make clean`
6. Run `diff -ru <temp-dir-a> <temp-dir-b>` to get the full diff
7. Clean up temp directories

Analyze the diff and present a structured summary:
- **Replica counts**: differences in deployment/statefulset replicas
- **Resource requests/limits**: CPU and memory differences
- **Retention/storage**: log retention, volume sizes
- **Feature flags**: features enabled in one env but not the other
- **Security posture**: policy enforcement modes, TLS settings
- **Other differences**: anything else notable

Present the raw diff only if the user asks for it or the summary is insufficient.
