"""catalog.py — the catalog's own charts, and the one way this repository renders them.

A chart under catalog/<name>/chart is a workload a tenant installs. No
ApplicationSet in this repository deploys one, so ArgoCD never renders it from
here, and every render made here stands in for a tenant's. What it stands in with
is catalog/<name>/ci-values.yaml, the inputs a tenant's Application supplies,
read beside the chart's own values.yaml.

This module is the one place that turns those into a `helm template` command.
CI's validate job and `task render` write the render through main();
check-serviceaccount-bindings.py and the image gates read it through render().
Written out separately, the command drifted: three renderers each spelled it,
and one of them passed a single input of the nine. With one definition, what
one gate checks is what the others check.

The population is every directory matching CHART_GLOB, derived rather than
listed, so a second catalog chart is rendered by everything that renders the
first.

Exit status: 0 when every chart rendered, 1 when a chart failed to render or has
no tenant inputs, and 2 (CANNOT_RUN) when helm is missing, a render ran out of
time, or no chart matched CHART_GLOB.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import gatelib

ROOT = Path(__file__).resolve().parent.parent
CHART_GLOB = "catalog/*/chart"

# Beside each chart's values.yaml: the inputs a tenant's Application supplies.
TENANT_INPUTS = "ci-values.yaml"

# The release every render uses. Each chart renders into <name>-ci, a namespace
# no cluster this catalog reaches runs a tenant in.
RELEASE = "ci"

# Seconds one `helm template` of a chart in this tree may take. It reads only the
# working tree, so running past this is a hang rather than a slow network.
RENDER_TIMEOUT = 120


class RenderFailed(Exception):
    """The chart, as this tree has it, does not render: a finding about the tree."""


class CannotRender(Exception):
    """helm did not finish, so nothing was decided about the chart."""


@dataclass(frozen=True)
class CatalogChart:
    root: Path
    chart_dir: Path

    @property
    def name(self) -> str:
        return self.chart_dir.parent.name

    @property
    def chart(self) -> str:
        """The name the image gates record a rendered image against."""
        return self.name

    @property
    def path(self) -> str:
        return self.chart_dir.relative_to(self.root).as_posix()

    @property
    def namespace(self) -> str:
        return f"{self.name}-{RELEASE}"

    @property
    def value_files(self) -> list[Path]:
        return [self.chart_dir.parent / "values.yaml", self.chart_dir.parent / TENANT_INPUTS]


def discover(root: Path = ROOT) -> list[CatalogChart]:
    return [CatalogChart(root, d) for d in sorted(root.glob(CHART_GLOB)) if d.is_dir()]


def template_command(chart: CatalogChart, env: str) -> list[str]:
    cmd = ["helm", "template", RELEASE, str(chart.chart_dir), "--namespace", chart.namespace]
    for values in chart.value_files:
        cmd += ["-f", str(values)]
    return cmd + ["--set", f"environment={env}"]


def render(chart: CatalogChart, env: str) -> str:
    """The chart's manifests for `env`, rendered with its tenant inputs."""
    missing = [v.relative_to(chart.root).as_posix() for v in chart.value_files if not v.is_file()]
    if missing:
        raise RenderFailed(
            f"{', '.join(missing)} does not exist. A catalog chart renders here with "
            f"values.yaml and the tenant inputs in {TENANT_INPUTS}, both beside it."
        )
    try:
        proc = subprocess.run(
            template_command(chart, env), capture_output=True, text=True, timeout=RENDER_TIMEOUT
        )
    except subprocess.TimeoutExpired as exc:
        raise CannotRender(
            f"helm template ran past the {RENDER_TIMEOUT}s a render of {chart.path} is allowed"
        ) from exc
    if proc.returncode != 0:
        raise RenderFailed((proc.stderr.strip() or proc.stdout.strip())[:1200])
    return proc.stdout


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Render every catalog chart with its tenant inputs.")
    ap.add_argument("--env", required=True, help="the environment value each render sets")
    ap.add_argument(
        "--out",
        required=True,
        help="where each render is written, with {name} for the chart, "
        "e.g. rendered/catalog-{name}-chart.yaml",
    )
    args = ap.parse_args(argv)
    if "{name}" not in args.out:
        ap.error("--out must contain {name}, or every chart would be written to one file")

    gatelib.require("helm")
    charts = discover()
    if not charts:
        print(f"Cannot run: no chart matched {CHART_GLOB}, so nothing was rendered.")
        return gatelib.CANNOT_RUN

    failed = 0
    for chart in charts:
        try:
            manifests = render(chart, args.env)
        except CannotRender as exc:
            print(f"Cannot run: {exc}.")
            return gatelib.CANNOT_RUN
        except RenderFailed as exc:
            print(f"FAIL  {chart.path} did not render for {args.env}:\n{exc}")
            failed += 1
            continue
        out = Path(args.out.format(name=chart.name))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(manifests)
        print(f"rendered {chart.path} for {args.env} to {out}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
