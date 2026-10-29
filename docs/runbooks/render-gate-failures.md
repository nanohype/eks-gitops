# Runbook — Render-Gate Failures on PRs

**Severity**: low (nothing is deployed — CI blocked the merge, which is the gate doing its job). **Scope**: the `validate` job in `.github/workflows/ci.yml`, which renders every kustomize root (per environment: development, staging, production, hub) plus the druid catalog chart with synthetic tenant values, then runs three gates over the *rendered* output; the `charts` job, which fetches every pinned chart for the jobs that render one; and the `image-vulnerabilities` job, which scans every image those charts render.

## Symptoms

- A PR check fails on one of: `Zero-placeholder gate`, `Lint YAML`, or a step inside `Validate (<env>)` — render, "Assert no unfilled sentinels", "Schema gate (kubeconform)", or "Misconfiguration gate (trivy config)"
- `Pinned chart archives` fails, or a job that waits on it (`needs: charts`) fails on a line naming a chart and its source, or is cancelled at its `timeout-minutes`
- `Rendered images carry no unacknowledged CRITICAL` exits 2 with "these images could not be scanned"
- `Assume the ECR Public pull role` or `Log in to public.ecr.aws` fails in `Pinned chart archives` or `Rendered images carry no unacknowledged CRITICAL`
- The PR summary comment shows a red row

## Diagnosis

Reproduce locally before reading CI logs twice — the Taskfile mirrors the pipeline:

```bash
task lint:yaml     # yamllint over the repo
task render        # kustomize + helm render into rendered/ (incl. druid chart)
task scan          # kubeconform + trivy config over rendered/
task validate      # lint + build combined
```

Then map the failing step to what it actually checks:

**Zero-placeholder / render-assert** — an unfilled sentinel (placeholder token, zero account id, account-less ARN) either in source files or appearing only after templating. The fix is always filling the real value; these gates exist precisely so a placeholder never reaches a cluster.

**Render failure** — `kustomize build --enable-helm` or `helm template` errored. Usual causes: overlay missing its `kustomization.yaml`, a `values-{env}.yaml` absent for one of the four environments, or (druid) a template change that breaks under the synthetic `--set` values in the workflow. Note the matrix renders *every* environment — a change that renders fine in development can still fail the hub leg.

**Schema gate (kubeconform)** — strict mode through `scripts/kubeconform-scan.sh`: native kinds from yannh/kubernetes-json-schema and CRD kinds from the datreeio CRDs-catalog, each read at the commit the script pins in `K8S_SCHEMA_REF` and `CRD_CATALOG_REF`, deliberately **no** `-ignore-missing-schemas`. Every rejected resource is printed with the file that carries it, and every non-zero exit ends with the two refs the run was pinned to. Three failure shapes:

- *"could not find schema for <Kind>"* — the kind is new to the repo and neither source knows it at the pinned ref. Options, in order of preference: the CRD exists in the datreeio catalog under a different group/version (fix the manifest's apiVersion); contribute the schema upstream to the CRDs-catalog and take the ref that carries it; or add the kind to `DEFAULT_SKIP` in `scripts/kubeconform-scan.sh` with a comment justifying it (the Grafana entry shows the shape — skips are per-kind, commented, and rare).
- *field/type errors* — a genuinely invalid manifest, or the catalog schema is stricter than the CRD actually deployed (the Grafana skip exists for exactly that mismatch). Verify against the real CRD before assuming the manifest is wrong.
- *an unchanged manifest failing on a ref bump* — the Renovate pull request that moves `K8S_SCHEMA_REF` or `CRD_CATALOG_REF` changes nothing else, so the schema moved and the manifest did not. Compare the two refs upstream (`https://github.com/datreeio/CRDs-catalog/compare/<old>...<new>`). A schema that was removed or broken upstream is fixed upstream, and the pull request waits for a ref that carries the fix; a schema that became stricter and matches the CRD actually deployed means the manifest was wrong all along.

**Chart fetch (`charts`, and every job that restores its cache)** — `scripts/render-addons.py --fetch` reads every chart pinned in `applicationsets/` through `scripts/registry.py` into `~/.cache/eks-gitops/charts`, and the same command reproduces it locally. The exit status says whose problem it is:

- *exit 1, "answered, and its answer rules the pin out"* — the registry replied: the pinned version is not there (HTTP 404), or the chart repository's `index.yaml` lists it with no archive or no digest to check the archive against. The pin is wrong for this repo, and re-running gets the same answer. Fix the version or the source in the ApplicationSet.
- *exit 2, "Cannot run: … could not be read"* — the registry could not be read: a timeout, a body cut off mid-read, an archive that did not hash to the digest the registry publishes, a token realm that refused the token request, a body still arriving when the call's deadline passed ("ran out while the body of … was arriving"), or an HTTP 429, 502, 503 or 504 that outlasted the client's retries or the call's deadline. Each wait before a retry is printed to stderr with the host and the status, as "request <n> of <attempts> answered HTTP <status>, retrying in …". Requests to a host named in `REQUEST_SPACING_SECONDS` in `scripts/registry.py` are also held apart by that spacing, which prints nothing. Nothing in the change is implicated.
- *exit 2, naming "the login `docker login` stored for" a host* — the host, or its token realm, refused that login with HTTP 401 or 403, and refused the same request made anonymously as well, so the read needs a login and the stored one does not serve. An ECR Public login lasts 12 hours, so one on a workstation is often stale; log in to the host again. A refusal the anonymous request does not repeat fails nothing: the host is read anonymously from then on, and stderr says so once, as "<host> refused the login `docker login` stored for it (…), so it is read anonymously".
- *cancelled at `timeout-minutes`* — one call through the client, its token request included, ends within `CALL_BOUND_SECONDS` in `scripts/registry.py`: its deadline, plus the one socket read a body still arriving then can have under way. Every job that reads through the client allows longer than that, so a cancellation is not one call a registry throttled or trickled a body to. It is the job's steps together outlasting the timeout, a registry that throttled call after call or a helm, kyverno or trivy subprocess running toward its own timeout, or one request a host held open while connecting or sending its status line and headers, which urlopen does with no check of the deadline between its socket waits. The step the log shows running last is the one that was cut off. Retry lines on its stderr name the throttling host; a step with none was waiting on a subprocess or on a host that had not answered.

The cache is keyed on `applicationsets/*.yaml` and `scripts/registry.py`. The `charts` job saves what it verified whether or not its fetch finished: a complete set under that key, `charts-<pins hash>`, and a set the fetch left incomplete under `charts-partial-<pins hash>-<run id>-<attempt>`. A rendering job restores only `charts-<pins hash>`, and a restore that misses a key exactly takes the newest key that begins with it, which no incomplete set's key does, so a rendering job restores a complete set or nothing. The `charts` job's restore takes the newest incomplete set for the same pins first, so a re-run fetches only the charts the attempt before it did not reach, and otherwise the newest set kept under any `charts-` key. Each archive sits beside a `.sha256` record of the digest it was verified against, and the client hands an archive out only while it still hashes to that record; one that does not is fetched again, with the line "cached, and not the bytes that were verified when it was kept; fetching it again". Every job that restores the cache declares `needs: charts`, so when the `charts` job fails they are skipped and the run fails on the `charts` job's own exit status. When it succeeds and a restore still misses — the cache was evicted, or saved under another key — that job fetches each chart itself from its own runner, and the run carries a "Chart cache miss" warning on that job.

**ECR Public login (`charts`, `image-vulnerabilities`)** — both jobs assume the role the `ECR_PUBLIC_PULL_ROLE_ARN` repo variable names over GitHub OIDC, then pipe `aws ecr-public get-login-password` into `docker login public.ecr.aws`, so their pulls are metered by that role's AWS account rather than by the runner's address. A run for a pull request from a fork, or with the variable unset, skips both steps and reads anonymously. With the variable set, a failure on either step fails the job rather than leaving it to read anonymously, and the step's log carries the error from the GitHub OIDC token endpoint, STS, ECR Public or `docker login`. A failure whose log shows throttling, a 5xx or a network error from one of them is transient, and re-running the failed jobs is the remedy. A failure that repeats on a re-run is the role, a trust or policy mismatch: the variable names a role this repository's OIDC token cannot assume, or one that cannot mint an ECR Public authorization token.

**Image scan (`image-vulnerabilities`)** — `scripts/check-image-vulnerabilities.py` scans each image the production render carries with trivy. An image trivy could not scan exits 2, named with the charts that render it, why, and the end of trivy's stderr. A registry refusing trivy with a 429 or a 5xx (`TOOMANYREQUESTS`, `UNAVAILABLE`, or `unexpected status code <status>` in that stderr) has already been tried `SCAN_ATTEMPTS` times, each wait printed as "attempt <n> of <attempts> was refused with …"; re-run the job. Any other stderr — `DENIED`, `MANIFEST_UNKNOWN`, a 401 or 404 — is a fact about the reference and is reported on the first attempt.

**Misconfiguration gate (trivy config)** — runs over `rendered/`, so every finding reflects post-templating truth with values applied. MEDIUM and above fails the build. The finding ID (`KSV-*`/`AVD-*`) plus the rendered file name tell you which addon and which check.

## Remediation

**Default: fix the manifest.** Most trivy findings have a direct fix — set the securityContext, add resources/probes, drop the capability, pin the tag. The gate severity floor is MEDIUM, so it isn't flagging trivia.

**Exception path: a reasoned `.trivyignore.yaml` entry.** Legitimate only when the flagged configuration *is the component's contract* — the existing entries are the calibration: a device plugin must run as root and hostPath-mount the kubelet socket (KSV-0012/0023); Druid's ConfigMap keys named `*Password` hold `${env:...}` indirection, not secret material (KSV-0109/01010); the overlord's namespace-scoped Role manages Jobs because that is what the k8s task runner does (KSV-0042 et al.). An entry must have all three:

```yaml
- id: KSV-XXXX
  paths:
    - "*<rendered-file-glob-for-exactly-this-addon>*"
  statement: >-
    Why this configuration is the component's contract, and where the
    compensating control lives if there is one.
```

- `paths` scoped to one addon's rendered output — never a bare `id` that suppresses the check repo-wide
- `statement` that survives a cold review: what the finding flags, why it's intentional, compensating control (e.g. registry findings point at the Kyverno verify-images policy)
- If you can't write that statement convincingly, it's a fix, not an ignore

**A chart that could not be fetched (exit 2, or a cancelled job): re-run the failed jobs.** ECR Public allows an unauthenticated client a fixed amount of data per month and identifies it by address, so an anonymous read from `public.ecr.aws` fails on a runner arriving with that allowance spent until a re-run lands on another one. A read is anonymous in a run that skipped the login, from a fork or with `ECR_PUBLIC_PULL_ROLE_ARN` unset. It is anonymous in any run in a job other than `charts` and `image-vulnerabilities`, the two that log in, that missed the chart cache and fetched for itself, which the run marks with a "Chart cache miss" warning on that job. And it is anonymous where `scripts/registry.py` could not use the login, or `public.ecr.aws` refused it, which its stderr says once in a line ending "read anonymously": one naming the docker config, and `public.ecr.aws` or every registry, for a login it could not use, and one beginning "public.ecr.aws refused the login" for a login refused. A logged-in read is metered by the role's AWS account instead, with no per-address allowance for another runner to reset, so a logged-in exit 2 comes from the causes listed under exit 2 above, a timeout, a cut-off body or a 429 or 5xx that outlasted the client's retries among them, and re-running is the remedy for those as well. Re-run the `charts` job first; the jobs waiting on it re-run with it, and it starts from the archives the failed attempt verified, so only the charts that attempt did not reach are fetched again. A chart that fails on every re-run from the same source, with the same status, is worth reading as a registry outage rather than retrying further.

**A pin the registry ruled out (exit 1): fix the pin.** Move `chartVersion` to a version the source lists, or point the source at where the chart moved. An HTTPS repository whose index publishes no digest for the pinned version cannot be verified, so the pin moves to a version or a source that publishes one.

**kubeconform skips** follow the same discipline in `DEFAULT_SKIP` in `scripts/kubeconform-scan.sh`: per-kind, commented with the concrete schema/CRD mismatch, nothing broader.

## Verification

```bash
task render && task scan     # clean locally
git add <files by name> && git commit ...
```

Push and confirm all four `Validate (<env>)` matrix legs pass — the PR summary comment goes green. For a new `.trivyignore.yaml` entry, also confirm the gate still fails on *other* findings (the entry's `paths` glob should match only the intended rendered file; `grep <id> rendered/ -r` against the trivy output is a quick sanity check that you scoped it tightly).
