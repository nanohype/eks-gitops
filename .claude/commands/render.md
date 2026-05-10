Render Kustomize manifests for inspection.

Ask the user which environment to render (dev, staging, or production). Default to dev if not specified via $ARGUMENTS.

Steps:
1. Run `make clean` to remove any previous rendered output
2. Run `make render ENVIRONMENT=<env>` to render all overlays for the chosen environment
3. List all files in `rendered/` with their sizes
4. Offer to show the contents of any specific rendered file

If rendering fails, diagnose the kustomize build error and suggest fixes.
