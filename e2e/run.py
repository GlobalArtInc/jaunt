#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from scenarios import ROTATION_SCENARIOS, SCENARIOS
from stand.cleanup import remove_everything
from stand.layout import OUT, ROTATION_NODES
from stand.report import Report
from stand.stand import Stand, slug

DEFAULT_IMAGES = ["debian:13", "rockylinux:9"]


def parse(argv):
    parser = argparse.ArgumentParser(description="Run the Jaunt end-to-end stand")
    parser.add_argument("images", nargs="*", help="node images, default: {}".format(" ".join(DEFAULT_IMAGES)))
    parser.add_argument("--keep", action="store_true", help="leave the containers running after the run")
    parser.add_argument("--down", action="store_true", help="remove the stand containers, network and volume and exit")
    parser.add_argument("--skip-build", action="store_true", help="reuse the Linux binaries of an earlier run")
    parser.add_argument("--only", action="append", default=[], help="run only the named scenarios (repeatable)")
    parser.add_argument("--web", action="store_true", help="drive the real console in Chromium (needs web-tests/node_modules)")
    parser.add_argument("--rotation", action="store_true", help="run the CA rotation scenarios on three nodes (one old agent)")
    parser.add_argument("--list", action="store_true", help="list the scenarios and exit")
    parser.add_argument(
        "--transfer-mib", type=int, default=int(os.environ.get("E2E_TRANSFER_MIB", "256")),
        help="size of the files moved by scp and rsync",
    )
    return parser.parse_args(argv)


def build_binaries(rotation=False):
    started = time.monotonic()
    done = subprocess.run(["bash", os.path.join(HERE, "build-binaries.sh")])
    if done.returncode == 0 and rotation:
        done = subprocess.run(["bash", os.path.join(HERE, "build-old-agent.sh")])
    print("INFO building the Linux binaries took {:.0f} s".format(time.monotonic() - started), flush=True)
    return done.returncode == 0


ROTATION_CERT_TTL_SECS = 120
ROTATION_AGENT_ENV = {"RUST_LOG": "info,jaunt::agent=debug"}


def rotation_selection(only):
    names = [name for name, _ in ROTATION_SCENARIOS]
    unknown = [name for name in only if name not in names]
    if unknown:
        raise SystemExit("unknown rotation scenario {}; choose from {}".format(", ".join(unknown), ", ".join(names)))
    last = max(names.index(name) for name in only)
    chosen = names[: last + 1]
    print("INFO the rotation scenarios build on each other: running {}".format(", ".join(chosen)), flush=True)
    return chosen


def run_image(image, args):
    if args.rotation:
        stand = Stand(image, transfer_mib=args.transfer_mib, keep=args.keep, nodes=ROTATION_NODES,
                      agent_env=ROTATION_AGENT_ENV)
        stand.cert_ttl_secs = ROTATION_CERT_TTL_SECS
        stand.log_dir = os.path.join(OUT, "logs", slug(image) + "-rotation")
        scenarios = ROTATION_SCENARIOS
    else:
        stand = Stand(image, transfer_mib=args.transfer_mib, keep=args.keep)
        scenarios = SCENARIOS
    report = Report(image)
    started = time.monotonic()
    try:
        stand.build_images()
        print("INFO images ready in {:.0f} s".format(time.monotonic() - started), flush=True)
        with report.step("the stand starts: idp, two TLS edges, jauntd, client, {} nodes".format(len(stand.nodes))):
            stand.up()
        if report.failed():
            return report
        for name, scenario in scenarios:
            if args.only and name not in args.only:
                continue
            print("SCENARIO [{}] {}".format(image, name), flush=True)
            try:
                scenario(stand, report)
            except Exception as error:
                with report.step("scenario {} aborted".format(name)) as step:
                    step.expect(False, "{}: {}".format(type(error).__name__, error))
    finally:
        try:
            if not args.only:
                from scenarios.hygiene import finish
                finish(stand, report)
            else:
                stand.collect_logs()
        except Exception as error:
            print("FAIL [{}] the final checks aborted: {}".format(image, error), flush=True)
        if report.failed():
            print("INFO logs of this run are in {}".format(stand.log_dir), flush=True)
        if not args.keep:
            with report.step("the stand is removed"):
                stand.down()
    return report


def main(argv):
    args = parse(argv)
    if args.rotation and args.only:
        args.only = rotation_selection(args.only)
    if args.list:
        for name, _ in ROTATION_SCENARIOS if args.rotation else SCENARIOS:
            print(name)
        return 0
    if args.down:
        try:
            remove_everything()
        except RuntimeError as error:
            print(error, file=sys.stderr)
            return 1
        return 0
    if not args.skip_build and not os.environ.get("E2E_SKIP_BUILD"):
        if not build_binaries(args.rotation):
            print("building the Linux binaries failed", file=sys.stderr)
            return 2
    if args.web and args.rotation:
        print("--web and --rotation cannot be combined", file=sys.stderr)
        return 2
    if args.web:
        import web
        report = web.run(args)
        print(report.table(), flush=True)
        return 1 if report.failed() else 0
    status = 0
    for image in args.images or DEFAULT_IMAGES:
        report = run_image(image, args)
        print(report.table(), flush=True)
        if report.failed():
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
