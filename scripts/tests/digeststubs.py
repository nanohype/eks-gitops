"""What the tests of scripts/check-digest-rewrite.sh share: stand-ins for the cluster.

scripts/tests/test_digest_rewrite.py drives each of the script's steps by
sourcing it, and scripts/tests/test_digest_rewrite_run.py runs the script whole.
Both put these stubs first on PATH and read back the same records, so no stub
can answer the steps one way and the whole run another.

Stubs named kubectl, date and sleep stand in for the cluster and the clock:
kubectl answers each call from files named for it and records the call, and the
clock moves only when a request is sent or the script sleeps. Stubs named
timeout, kind and helm record what runs under a bound and what the bound was.
"""

from __future__ import annotations

import pathlib
import shutil
import tempfile
import unittest

from shellgate import identity_message, verifier_line

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "scripts" / "check-digest-rewrite.sh"

IDENTITY = identity_message()

# What the main body reads out of the fixtures, the appset and ci.yml: a tag, a
# foreign image pinned by digest, and the chart. The steps are handed these by
# hand, and the whole run's checkout is written with them.
TAGGED = "ghcr.io/nanohype/x:1.0.0"
FOREIGN = f"ghcr.io/nanohype/x@sha256:{'0' * 64}"
PINNED = f"{TAGGED}@sha256:{'a' * 64}"
CHART_VERSION = "0.0.0"

# The clock's reading when a run starts, and the seconds it moves across each
# create or patch: a request the API server takes that long to answer.
START = 1000
STEP = 10

# Bash builtins only, so it answers the same whatever else is on PATH. A call is
# keyed by its subcommand and what it names: the fixture a -f reads, the
# ephemeral container a patch adds, and which listing a get makes. The key's
# answer is the files under answers/ named for it, holding what the call prints,
# what it writes to stderr and the status it exits with. Each call is recorded
# with the clock's reading when it was made, as one line appended in one write:
# two kubectl calls on one pipe run at once, and a record written in parts
# interleaves with the other's. A create or patch moves the clock; one run with
# --dry-run=client sends the API server nothing, so it does not, and the
# kubectl reading its output on the same pipe reads a clock no one is writing.
KUBECTL = r"""#!BASH
work='WORK'
sub="" base="" prev=""
for a in "$@"; do
  [ "$prev" = -f ] && { base="${a##*/}"; base="${base%.yaml}"; }
  case "$a" in -*) ;; *) [ -n "$sub" ] || sub="$a" ;; esac
  prev="$a"
done
case "$sub $* " in
  "patch "*'"name":"pinned"'*) key=patch-pinned ;;
  "patch "*'"name":"foreign"'*) key=patch-foreign ;;
  "get "*" events "*) key=get-events ;;
  "get "*" -o name "*) key=get-pods ;;
  "get "*" pod "*) key=get-pod ;;
  *) key="$sub${base:+-$base}" ;;
esac
printf -v record '%s\x1f' "$(<"$work/now")" "$key" "$@"
printf '%s\n' "$record" >>"$work/calls"
answer="$work/answers/$key"
[ -f "$answer.out" ] && printf '%s\n' "$(<"$answer.out")"
[ -f "$answer.err" ] && printf '%s\n' "$(<"$answer.err")" >&2
case "$sub $* " in
  *" --dry-run=client "*) ;;
  "create "*|"patch "*) echo "$(( $(<"$work/now") + STEP ))" >"$work/now" ;;
esac
[ -f "$answer.rc" ] && exit "$(<"$answer.rc")"
exit 0
"""

# GNU timeout's shape, `timeout [OPTION]... DURATION COMMAND...`. What precedes
# the command is recorded as the bounds it was given, with the command after
# them, as kubectl's calls are: one line, appended in one write.
# answers/timeout-<command>.rc stands for the bound ending that command: the stub
# exits with it and runs nothing.
TIMEOUT = r"""#!BASH
work='WORK'
bounds=()
while [ "$#" -gt 0 ]; do
  case "$1" in kubectl|kind|helm) break ;; esac
  bounds+=("$1"); shift
done
printf -v record '%s\x1f' "${bounds[@]}" "$@"
printf '%s\n' "$record" >>"$work/bounded"
[ -f "$work/answers/timeout-$1.rc" ] && exit "$(<"$work/answers/timeout-$1.rc")"
exec "$@"
"""

# kind and helm, answering every call with success.
TOOL = r"""#!BASH
exit 0
"""

DATE = r"""#!BASH
printf '%s\n' "$(<'WORK/now')"
"""

SLEEP = r"""#!BASH
echo "$(( $(<'WORK/now') + $1 ))" >'WORK/now'
"""


def log(error: str) -> str:
    """A verifier line as the admission controller writes it, naming the image."""
    return verifier_line(error, f"image=ghcr.io/nanohype/x@sha256:{'0' * 64}")


def kubectl_said(message: str, reason: str = "Forbidden") -> str:
    """What kubectl writes for an answer the API server sent, carrying `message`."""
    return f"Error from server ({reason}): {message}"


# The API server's refusal under the policy's identity message, and as kubectl
# reports it.
IDENTITY_REFUSAL = (
    f'admission webhook "ivpol.validate.kyverno.svc-fail" denied the request: '
    f"Policy verify-images failed: {IDENTITY}"
)
DENIED = kubectl_said(IDENTITY_REFUSAL)

MISMATCH = log(
    "failed to verify cosign signatures: no matching signatures: none of the "
    "expected identities matched what was in the certificate"
)


class StubbedCluster(unittest.TestCase):
    """A scratch directory holding the stubs, their answers and their records."""

    def setUp(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not on PATH")
        self.bash = bash
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = pathlib.Path(tmp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        (self.work / "answers").mkdir()
        (self.work / "now").write_text(f"{START}\n")
        for name, body in (
            ("kubectl", KUBECTL),
            ("date", DATE),
            ("sleep", SLEEP),
            ("timeout", TIMEOUT),
            ("kind", TOOL),
            ("helm", TOOL),
        ):
            stub = self.bin / name
            stub.write_text(
                body.replace("BASH", bash, 1)
                .replace("WORK", str(self.work))
                .replace("STEP", str(STEP))
            )
            stub.chmod(0o755)

    def answer(self, key: str, out: str | None = None, err: str | None = None, rc: int = 0) -> None:
        """What the kubectl call keyed `key` prints, writes to stderr and exits with."""
        for suffix, value in (("out", out), ("err", err), ("rc", str(rc) if rc else None)):
            if value is not None:
                (self.work / "answers" / f"{key}.{suffix}").write_text(value)

    def calls(self) -> list[tuple[int, str, list[str]]]:
        """Each kubectl call: the clock when it was made, its key and its argv."""
        path = self.work / "calls"
        if not path.exists():
            return []
        out = []
        for line in path.read_text().splitlines():
            clock, key, *argv = line.split("\x1f")[:-1]
            out.append((int(clock), key, argv))
        return out

    def calls_to(self, key: str) -> list[list[str]]:
        return [argv for _, k, argv in self.calls() if k == key]

    def bounded(self) -> list[tuple[list[str], list[str]]]:
        """Each command run under timeout: the bounds it was given, and the command."""
        path = self.work / "bounded"
        if not path.exists():
            return []
        out = []
        for line in path.read_text().splitlines():
            fields = line.split("\x1f")[:-1]
            at = next(i for i, f in enumerate(fields) if f in ("kubectl", "kind", "helm"))
            out.append((fields[:at], fields[at:]))
        return out
