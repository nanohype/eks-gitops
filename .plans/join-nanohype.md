# Join nanohype org

Tactical plan for moving `stxkxs/eks-gitops` → `nanohype/eks-gitops`.

Master plan: `/Users/bs/.claude/plans/so-i-want-to-snazzy-sun.md` Phase 1.2.

## Transfer

```sh
gh repo transfer stxkxs/eks-gitops nanohype
git remote set-url origin git@github.com:nanohype/eks-gitops.git
```

## Cross-references to fix

```sh
grep -rn "stxkxs" --include="*.md" --include="*.yaml" --include="*.json"
```

Known references:

- `CLAUDE.md:5` — references `aws-eks` as the CDK companion. **Open question (master plan Phase 1.2):** verify whether `aws-eks` is a distinct repo, or refers to `cdk-constructs`, or is dead. If distinct & surviving, transfer that too; if it's `cdk-constructs`, this reference dies with cdk-constructs in Phase 4
- `CLAUDE.md:77` — "Relationship to Parent Repo" section names `aws-eks` again
- Docs in `docs/` may link to companion repos

## App-of-Apps pointer

The EKS infrastructure repo creates an ArgoCD `Application` that points to this repo's `applicationsets/` directory. After transfer, that pointer must update to `https://github.com/nanohype/eks-gitops`. This change lives in whichever repo creates the bootstrap Application (likely `cdk-constructs` or its successor in `landing-zone`).

## ApplicationSet repo references

Inspect every ApplicationSet in `applicationsets/`:

```sh
grep -rn "stxkxs\|github.com/.*eks-gitops" applicationsets/
```

If any reference this repo's URL directly (rather than via the App-of-Apps `repoURL` parameter), update.

## Verification

```sh
gh repo view nanohype/eks-gitops                                       # 200
task validate                                                          # still passes
grep -rn "stxkxs" --include="*.md" --include="*.yaml"                  # zero or intentional only
```

## Notes

- Helm chart references go to upstream repos (artifacthub, OCI registries) — no org coupling
- `.github/workflows/{ci,diff}.yml` — check for hardcoded org refs in PR-summary comment posting
- Cluster secret labels (set by the EKS infrastructure repo) drive environment selection — no change needed here
