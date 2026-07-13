# Opt-in ApplicationSets

These ApplicationSets are **not** applied by a default install. They live in this
subdirectory deliberately: the `app-of-apps` Application sources `path:
applicationsets` **without `directory.recurse`**, so ArgoCD applies only the
top-level manifests there and never descends into this folder.

They are parked here because each one depends on infrastructure that a base
cluster does not have. Shipping them in the default path meant every install —
including one vended into a different GitHub org — instantiated ApplicationSets
that could never generate, leaving them permanently `ErrorOccurred` and dragging
`app-of-apps` (and therefore the whole install) to `Degraded`.

| ApplicationSet | Requires |
|---|---|
| `clusters-appset.yaml` | The private clusters repo over SSH, **and the hub cluster** — it applies eks-fleet `Cluster` CRs, which only exist where the Cluster API + Crossplane run. On a workload/spoke cluster it can never be correct. |
| `portal-tenants.yaml` | The private tenants repo over SSH, plus an ArgoCD SSH repo credential (a read-only deploy key) registered for that URL. |
| `apps-tenants.yaml` | One `AppProject` per tenant app (the template sets `project: {{ .app }}`), plus read access to each app's source repo. |

## Enabling them

They are ordinary ApplicationSets — nothing about them is special beyond the
prerequisites above. To turn them on for an install that genuinely has the
portal, the private repos, and (for `clusters-appset`) the hub:

1. Register the SSH repo credentials in ArgoCD for the clusters/tenants repos
   (a read-only deploy key per repo). `cluster-bootstrap` does this when
   `tenants_repo_url` is set.
2. Create the per-app `AppProject`s that `apps-tenants` references.
3. Point an Application at this path — either add a second app-of-apps whose
   source `path` is `applicationsets/opt-in`, or set `directory.recurse` on the
   existing one (which pulls in everything here, so prefer the explicit path).

## Before enabling, re-check the hardcoded repo URLs

`clusters-appset.yaml` and `portal-tenants.yaml` hardcode `git@github.com:` URLs,
and `apps-tenants.yaml` hardcodes its four app source repos. An install in a
different GitHub org must repoint these — they are not templated from the cluster
Secret today.
