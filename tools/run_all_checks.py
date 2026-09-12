#!/usr/bin/env python3
"""Run every interop/self-test suite in one go.

    python3 tools/run_all_checks.py

The Node based suites need ``tools/interop/node_modules`` (see
``tools/interop/package.json``); they are skipped with a warning when the
directory is missing.  The pure Python suites always run.
"""

from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INTEROP = os.path.join(ROOT, "tools", "interop")
SUITES = [
    ("unit tests (bot runtime + plugins)", [sys.executable, "tests/test_bot.py"]),
    ("binary node codec", [sys.executable, "tools/interop/check_binary.py"]),
    ("protobuf codec", [sys.executable, "tools/interop/check_proto.py"]),
    ("signal protocol", [sys.executable, "tools/interop/check_signal.py"]),
    ("qr encoder", [sys.executable, "tools/interop/check_qr.py"]),
    ("client end to end (fake WhatsApp server)", [sys.executable, "tools/interop/check_client.py"]),
]


def main() -> int:
    node_modules = os.path.join(INTEROP, "node_modules")
    have_node = os.path.exists(node_modules)
    if not have_node:
        print("! tools/interop/node_modules is missing: Node based checks may fail\n"
              "  run `npm install` inside tools/interop first\n")

    results = []
    for name, command in SUITES:
        print(f"\n=== {name} " + "=" * max(0, 60 - len(name)))
        if not os.path.exists(os.path.join(ROOT, command[1])):
            print("skipped (script not present)")
            results.append((name, None))
            continue
        process = subprocess.run(command, cwd=ROOT)
        results.append((name, process.returncode == 0))

    print("\n" + "=" * 64)
    for name, status in results:
        print(f"{'PASS' if status else 'FAIL' if status is False else 'skip':4}  {name}")
    failed = [name for name, status in results if status is False]
    print("=" * 64)
    print("all checks passed" if not failed else f"{len(failed)} suite(s) failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
