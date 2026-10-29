"""Every verdict the two gates on the image-verification path reach.

scripts/kyverno-test.sh reads Kyverno's verifier through the CLI's table and
log, and scripts/check-digest-rewrite.sh reads it through the API server's
refusal and the admission controller's log. Both run their commands and hand
what came back here, one subcommand per question: the sentence to print goes to
standard output and the verdict is the exit status. What either gate concludes
about verification is decided in this file, so each conclusion is reachable from
scripts/tests/test_verdicts.py without a cluster, a registry or the Kyverno CLI.

  0  the verdict holds
  2  the run could not decide, and the sentence says why (gatelib.CANNOT_RUN)
  3  a finding: the gate fails
  4  ask again: run the suite again, or read the verifier's log and ask with it

No failure of the interpreter produces 0, 3 or 4. A traceback exits 1, and an
interpreter that cannot open this file, or a call it cannot parse, exits 2. Each
caller reads every status outside those four as a run that could not decide, so
no failure here reads as a pass or as a finding.

Standard library only, beside gatelib, so it runs on whichever python3 a job has.
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import re
import sys
from collections.abc import Callable, Sequence

import gatelib

HOLDS = 0
CANNOT_RUN = gatelib.CANNOT_RUN
FINDING = 3
AGAIN = 4

# A verdict: the exit status, and the lines that say what it means.
Verdict = tuple[int, list[str]]

# ── Transport failures ───────────────────────────────────────────────────────

# A transport failure on the image-verification path, as Go's HTTP client,
# go-containerregistry reading the registry, the Sigstore TUF client fetching the
# trusted root and the Rekor client word one. Both gates read the same verifier
# through this one pattern: a phrase only one of them knew would be an outage
# that one reports as a run that could not verify and the other as a verdict on
# a signature. Matched ignoring case.
TRANSPORT_FAILURE = re.compile(r"dial tcp|no such host|i/o timeout|connection refused|connection reset|broken pipe|TLS handshake timeout|context deadline exceeded|Client\.Timeout exceeded|unexpected EOF|tuf: failed to download|unexpected status code (?:429|5[0-9][0-9])|toomanyrequests|\]\[(?:429|5[0-9][0-9])\]", re.IGNORECASE)

# The terminal colour codes zerolog's console writer, which the verifier logs
# through, wraps field names and values in.
COLOUR = re.compile("\x1b\\[[0-9;]*m")

# How a diagnostic quotes a line naming a transport failure: from up to CONTEXT
# characters before its first phrase, at most WIDTH characters of it, and at most
# QUOTED distinct lines in all.
CONTEXT = 60
WIDTH = 240
QUOTED = 3

# The indent a quoted line carries under the sentence it supports.
INDENT = " " * 8


def lines_of(text: str) -> list[str]:
    """The lines of `text`. A final newline ends the last line rather than opening one."""
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def uncoloured(text: str) -> str:
    """`text` with its terminal colour codes cut away."""
    return COLOUR.sub("", text)


def transport_failures(text: str) -> list[str]:
    """Each line of `text` naming a transport failure, as a diagnostic quotes it.

    Empty when `text` names none, which is the answer each caller decides on.
    """
    quoted: list[str] = []
    for line in lines_of(uncoloured(text)):
        found = TRANSPORT_FAILURE.search(line)
        if found is None:
            continue
        excerpt = line[max(0, found.start() - CONTEXT):][:WIDTH]
        if excerpt in quoted:
            continue
        quoted.append(excerpt)
        if len(quoted) == QUOTED:
            break
    return quoted


# ── Bounds ───────────────────────────────────────────────────────────────────

# GNU timeout's status for a command it ended: TIMED_OUT when its TERM did, and
# KILLED when the command was still going the kill grace later and was killed.
# A command killed for any other reason exits KILLED too. None of them finished,
# so none decided anything, whatever it had printed.
TIMED_OUT = 124
KILLED = 137


def ended_by_bound(command: str, status: int, seconds: int) -> str:
    """The sentence saying a bound ended `command`, or "" when it ended on its own.

    A command the bound ended has written nothing that says so, so this sentence
    is the only record of it.
    """
    if status == TIMED_OUT:
        return f"{command} did not finish within {seconds}s, so GNU timeout ended it."
    if status == KILLED:
        return f"{command} was killed before it finished."
    return ""


# ── The Kyverno suite ────────────────────────────────────────────────────────

# What curl's status code from an endpoint on the verification path must be for
# the image-verification rows to decide on a signature: any success, or the
# registry's 401 challenge to a request carrying no token.
REACHABLE = re.compile(r"2[0-9][0-9]|401")


def endpoint(url: str, status: str) -> Verdict:
    """Whether `url` answered, before any row is run against it."""
    if REACHABLE.fullmatch(status):
        return HOLDS, []
    return CANNOT_RUN, [
        f"Cannot run: {url} answered '{status or 'nothing'}', so the image-verification",
        "rows would decide on an unreachable registry or log rather than on a signature.",
    ]


def kyverno_run(output: str, status: int, attempt: int, attempts: int, seconds: int) -> Verdict:
    """Whether attempt `attempt` of `attempts` at `kyverno test` decided its rows.

    An ImageValidatingPolicy row verifies a real signature, and a transport
    failure on that path reaches the table two ways. Reading the image fails the
    row as "got error", with the transport error as its message. Anything after
    that is counted as a signature that did not verify, so the row reports the
    policy's own message and only the verifier's log names the cause. `output`
    is both: the table with its message column, and the log the suite runs at
    -v 1.

    A run carrying a transport failure anywhere, or one a bound of `seconds`
    ended, decided none of those rows either way. It is run again, and a
    transport failure in every one of `attempts` runs is a suite that could not
    verify. A run carrying none HOLDS, and is decided on its rows by the caller.
    """
    ended = ended_by_bound("kyverno test", status, seconds)
    reasons = [ended] if ended else transport_failures(output)
    if not reasons:
        return HOLDS, []
    quoted = [f"      {reason}" for reason in reasons]
    if attempt >= attempts:
        return CANNOT_RUN, [
            f"Cannot run: all {attempts} runs met a transport failure on the image-verification",
            "path, so no image-verification row above was decided by a signature. The last:",
            *quoted,
        ]
    return AGAIN, [
        f"Attempt {attempt} of {attempts} met a transport failure, so its image-verification",
        "rows decided nothing; running the suite again:",
        *quoted,
    ]


# ── Admission ────────────────────────────────────────────────────────────────

# The message verify-images refuses an image under when no release signature
# verifies. scripts/tests/test_verdicts.py holds it to the policy's own.
IDENTITY_MESSAGE = "image is not signed by a nanohype release workflow"

# The message Kyverno's cosign verifier logs every failed verification under,
# through logr's Error, which no verbosity setting suppresses.
VERIFIER_FAILED = "image verification failed"

# How a refusal that carries an answer begins: kubectl writes the API server's as
# "Error from server", and a ReplicaSet writes each refusal of its pod as a
# FailedCreate event beginning "Error creating:".
ANSWERED = re.compile(r"^Error (?:from server|creating:)", re.MULTILINE)

# What the API server writes for an admission webhook it got no answer from.
WEBHOOK_UNANSWERED = "failed calling webhook"


@dataclasses.dataclass(frozen=True)
class Refusal:
    """A request the API server or kubectl refused, and what it is read beside.

    `log` is what every admission-controller replica logged from before the
    request was sent, or None until the caller has read it.
    """

    what: str
    overlay: str
    root: str
    request_timeout: int
    text: str
    log: str | None = None


def shown(refusal: Refusal) -> list[str]:
    """The refusal as a diagnostic quotes it, with the checkout's path elided."""
    return [f"{INDENT}{line.replace(refusal.root + '/', '')}"[:WIDTH]
            for line in lines_of(refusal.text)]


def verifier_lines(log: str) -> list[str]:
    """The verifier's lines in what the admission controller logged, uncoloured.

    The controller's webhook server logs its own connection errors to the same
    stream, a TLS handshake error as the API server drops a connection among
    them, and those name no verification. Only a line naming a failed
    verification is the verifier's.
    """
    return [line for line in lines_of(uncoloured(log)) if VERIFIER_FAILED in line]


def broken_link(refusal: Refusal) -> str:
    """Which link a transport failure the refusal itself names broke.

    A refusal carrying no answer is kubectl's own request ending before one
    came: its bound passed or its connection failed, and no admission ran. One
    the API server wrote on failing to call a webhook is that call. Any other is
    the verifier's reads of the registry, the trusted root and Rekor.
    """
    if not ANSWERED.search(refusal.text):
        return (f"{refusal.overlay}: kubectl's request for {refusal.what} ended with no answer "
                f"from the API server:\nits {refusal.request_timeout}s bound passed or its "
                f"connection failed.")
    if WEBHOOK_UNANSWERED in refusal.text:
        return (f"{refusal.overlay}: the API server got no answer from Kyverno's admission "
                f"webhook for {refusal.what}.")
    return unreachable(refusal)


def unreachable(refusal: Refusal) -> str:
    return (f"{refusal.overlay} could not reach the registry, the Sigstore trusted root or "
            f"Rekor for {refusal.what}.")


def refusal_cause(refusal: Refusal) -> Verdict:
    """HOLDS once the refusal's cause is established, and otherwise why it is not.

    The cluster states a refusal's cause in the same two places the Kyverno CLI
    does. Reading the image failing refuses the request with the transport error
    as the API server's message. A failure after that, fetching the Sigstore
    trusted root, a Rekor lookup or reading the signature's manifest, is counted
    as a signature that did not verify, so the refusal carries the policy's own
    identity message and only the verifier's log names the cause.

    So the refusal is read first, and a transport failure there is named by the
    link it broke. Without one, the verifier's log decides, and the caller is
    asked to read it: a request kubectl got no answer for is never followed by a
    read of a log no admission wrote to. A transport failure in the log leaves the
    run unable to decide, and so does a refusal carrying the identity message with
    no verifier line behind it. A failed verification always logs one, so a log
    without one is not the verifier's, and its silence says nothing about whether
    the identity or an outage refused the request.
    """
    cause = transport_failures(refusal.text)
    if cause:
        return CANNOT_RUN, [*shown(refusal), *(f"{INDENT}{c}" for c in cause),
                            f"Cannot run: {broken_link(refusal)}"]
    if refusal.log is None:
        return AGAIN, []
    lines = verifier_lines(refusal.log)
    cause = transport_failures("\n".join(lines))
    if cause:
        return CANNOT_RUN, [*shown(refusal), *(f"{INDENT}{c}" for c in cause),
                            f"Cannot run: {unreachable(refusal)}"]
    if IDENTITY_MESSAGE in refusal.text and not lines:
        return CANNOT_RUN, [
            *shown(refusal),
            f"Cannot run: {refusal.overlay} refused {refusal.what} with the identity message, "
            f"but the admission\ncontroller's log carries no '{VERIFIER_FAILED}' line, so whether "
            f"the identity or\nan outage refused it is unknown.",
        ]
    return HOLDS, []


def release_signed_refused(refusal: Refusal, means: str) -> Verdict:
    """A release-signed submission refused: a finding once its cause is established.

    `means` says what the refusal costs. A cause left unknown ends the run here as
    it does for a foreign identity, whichever step made the request.
    """
    status, said = refusal_cause(refusal)
    if status != HOLDS:
        return status, said
    return FINDING, [f"  FAIL  {means}:", *shown(refusal)]


def foreign_identity(refusal: Refusal, admitted: bool, actions: str) -> Verdict:
    """A foreign identity, decided as the overlay's validationActions say.

    `actions` is the comma-separated list the rendered policy carries. One
    including Deny refuses the identity with the policy's identity message, and
    any other admits it and reports it. A refusal for any other reason is a
    finding, once its cause is established.
    """
    blocks = "Deny" in actions.split(",")
    if admitted:
        if blocks:
            return FINDING, [f"  FAIL  admitted {refusal.what} under Deny."]
        return HOLDS, [f"  ok    admitted {refusal.what} under {actions} (reported, not blocked)"]
    status, said = refusal_cause(refusal)
    if status != HOLDS:
        return status, said
    if IDENTITY_MESSAGE not in refusal.text:
        return FINDING, [f"  FAIL  {refusal.what} was refused for a reason other than its "
                         f"identity:", *shown(refusal)]
    if blocks:
        return HOLDS, [f"  ok    denied {refusal.what}: {IDENTITY_MESSAGE}"]
    return FINDING, [f"  FAIL  denied {refusal.what} under {actions}, which reports and does "
                     f"not block."]


# Verification and execution resolve a tag separately, so a tag admitted without
# the digest verification resolved runs whatever the tag names when it is pulled.
RESOLVED_TWICE = (
    "        Verification and execution then resolve the tag separately, and anyone",
    "        able to move it between those two moments runs an unverified image under",
    "        a policy reporting success.",
)

# Where an admitted image is read, as a verdict names it, and what an image
# there without a digest costs beyond the pin itself.
PIN_SITES: dict[str, tuple[str, tuple[str, ...]]] = {
    "init-container": ("{tagged} in the init container", RESOLVED_TWICE),
    "container": ("{tagged} in the container", RESOLVED_TWICE),
    "ephemeral-container": ("{tagged} as an ephemeral container", ()),
    "deployment-pod": ("the Deployment's pod", (
        "        A controller-created pod is the one that runs, and it must carry the",
        "        digest admission verified.",
    )),
}


def pinned(tagged: str, image: str) -> bool:
    """`image` is `tagged` joined to a sha256 digest, and nothing else."""
    return re.fullmatch(re.escape(tagged) + r"@sha256:[0-9a-f]{64}", image) is not None


def pin(site: str, tagged: str, image: str) -> Verdict:
    """Whether admission wrote the digest it verified beside the tag at `site`."""
    subject, costs = PIN_SITES[site]
    subject = subject.format(tagged=tagged)
    if pinned(tagged, image):
        return HOLDS, [f"  ok    admitted {subject} as {image}"]
    return FINDING, [f"  FAIL  admitted {subject} as '{image}', with no digest joined to the "
                     f"tag.", *costs]


# ── Command line ─────────────────────────────────────────────────────────────


def read(path: str) -> str:
    """A file a caller wrote a refusal or a log into, whatever bytes it holds."""
    return pathlib.Path(path).read_bytes().decode("utf-8", errors="replace")


def standard_input() -> str:
    """What a caller piped in, whatever bytes it holds."""
    return sys.stdin.buffer.read().decode("utf-8", errors="replace")


def refusal_of(args: argparse.Namespace) -> Refusal:
    log = None
    if args.log is not None:
        log = read(args.log)
    return Refusal(what=args.what, overlay=args.overlay, root=args.root,
                   request_timeout=args.request_timeout, text=read(args.refusal), log=log)


def answer_bound(args: argparse.Namespace) -> Verdict:
    sentence = ended_by_bound(args.command, args.status, args.seconds)
    if not sentence:
        return HOLDS, []
    return HOLDS, [sentence]


def answer_endpoint(args: argparse.Namespace) -> Verdict:
    return endpoint(args.url, args.status)


def answer_kyverno_run(args: argparse.Namespace) -> Verdict:
    return kyverno_run(standard_input(), args.status, args.attempt, args.attempts, args.seconds)


def answer_pinned(args: argparse.Namespace) -> Verdict:
    return pin(args.site, args.tagged, args.image)


def answer_release_signed(args: argparse.Namespace) -> Verdict:
    return release_signed_refused(refusal_of(args), args.means)


def answer_foreign_identity(args: argparse.Namespace) -> Verdict:
    return foreign_identity(refusal_of(args), args.outcome == "admitted", args.actions)


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="verdicts.py",
        description="Every verdict the two gates on the image-verification path reach.")
    questions = ap.add_subparsers(dest="question", required=True)

    # What a question about a refusal is read beside.
    refused = argparse.ArgumentParser(add_help=False)
    refused.add_argument("--what", required=True, help="what was refused")
    refused.add_argument("--overlay", required=True,
                         help="the overlay the request went through, relative to the checkout")
    refused.add_argument("--root", required=True,
                         help="the checkout, as the paths in the refusal spell it")
    refused.add_argument("--request-timeout", type=int, required=True,
                         help="the seconds kubectl's request was bounded by")
    refused.add_argument("--refusal", required=True, help="a file holding the refusal")
    refused.add_argument("--log", help="a file holding what the admission controller logged")

    def ask(name: str, answer: Callable[[argparse.Namespace], Verdict],
            parents: Sequence[argparse.ArgumentParser] = ()) -> argparse.ArgumentParser:
        sub = questions.add_parser(name, parents=list(parents))
        sub.set_defaults(answer=answer)
        return sub

    sub = ask("bound", answer_bound)
    sub.add_argument("--command", required=True)
    sub.add_argument("--status", type=int, required=True)
    sub.add_argument("--seconds", type=int, required=True)

    sub = ask("endpoint", answer_endpoint)
    sub.add_argument("--url", required=True)
    sub.add_argument("--status", required=True, help="the status code curl wrote")

    sub = ask("kyverno-run", answer_kyverno_run)
    sub.add_argument("--status", type=int, required=True)
    sub.add_argument("--attempt", type=int, required=True)
    sub.add_argument("--attempts", type=int, required=True)
    sub.add_argument("--seconds", type=int, required=True, help="the bound the run ran under")

    sub = ask("pinned", answer_pinned)
    sub.add_argument("--site", choices=sorted(PIN_SITES), required=True)
    sub.add_argument("--tagged", required=True)
    sub.add_argument("--image", required=True)

    sub = ask("release-signed", answer_release_signed, [refused])
    sub.add_argument("--means", required=True, help="what the refusal costs")

    sub = ask("foreign-identity", answer_foreign_identity, [refused])
    sub.add_argument("--outcome", choices=["admitted", "refused"], required=True)
    sub.add_argument("--actions", required=True, help="the overlay's validationActions")
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    """Answer the question `argv` asks: print what it means, and return the verdict."""
    args = parser().parse_args(argv)
    status, said = args.answer(args)
    for line in said:
        print(line)
    return status


if __name__ == "__main__":
    sys.exit(main())
