#!/usr/bin/env python3
"""
Inline registrar/passwordsafe.py into the operator scripts, producing
single-file tools under dist/ that run anywhere with nothing but Python 3.

Why this exists: the scripts import passwordsafe.py from a sibling directory,
which works fine inside the repo and fails the moment someone scp's one file
onto a jump box -- the usual way these get run in anger:

    ModuleNotFoundError: No module named 'passwordsafe'

Rather than lecture people about PYTHONPATH, ship artifacts that cannot
have the problem. passwordsafe.py is stdlib-only, so the result has zero
dependencies and needs no venv.

    python3 scripts/build-standalone.py
    scp dist/preflight.py root@host:/home/

Also embeds the config, so --team keeps working with no repo present.
"""

import datetime
import json
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
LIB = REPO / "registrar" / "passwordsafe.py"
DIST = REPO / "dist"

TARGETS = ["preflight.py", "fetch-credential.py",
           "bootstrap-functional-account.py"]

BANNER = """\
# ---------------------------------------------------------------------------
# GENERATED FILE -- do not edit.
# Built by scripts/build-standalone.py from:
#   scripts/{src}
#   registrar/passwordsafe.py
# Edit those and rebuild. Self-contained: stdlib only, no repo needed.
# ---------------------------------------------------------------------------
"""


def strip_module_docstring(text):
    """Drop passwordsafe.py's docstring so the merged file has exactly one."""
    m = re.match(r'\s*(?:"""|\'\'\')', text)
    if not m:
        return text
    quote = text[m.end() - 3:m.end()]
    end = text.index(quote, m.end())
    return text[end + 3:].lstrip("\n")


def inline_config(text):
    """Replace the config file read with an embedded dict literal."""
    configs = {}
    for f in sorted((REPO / "config").glob("*.json")):
        configs[f.stem] = json.loads(f.read_text())

    # Embed as a JSON STRING parsed at runtime, not as a Python literal.
    # json.dumps emits false/true/null, which are valid Python *syntax*
    # (they parse as bare identifiers) but blow up with NameError when the
    # line actually executes -- so py_compile happily accepts a broken file.
    blob = json.dumps(configs, indent=4)
    assert "'''" not in blob, "config contains a triple quote; escape it"
    literal = (
        "EMBEDDED_CONFIG = json.loads(r'''\n" + blob + "\n''')\n"
        "\n\ndef _load_config(team):\n"
        "    if team not in EMBEDDED_CONFIG:\n"
        "        raise SystemExit(\n"
        "            f'unknown team {team!r}. This standalone build knows: '\n"
        "            f'{sorted(EMBEDDED_CONFIG)}')\n"
        "    return EMBEDDED_CONFIG[team]\n"
    )

    text = re.sub(
        r'json\.loads\(\(REPO / "config" / f"\{args\.team\}\.json"\)\.read_text\(\)\)',
        "_load_config(args.team)",
        text,
    )
    return text, literal


def build(name):
    src = (REPO / "scripts" / name).read_text()
    lib = strip_module_docstring(LIB.read_text())

    # keep the tool's own docstring, then splice the library in beneath it
    src = src.replace(
        'sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent '
        '/ "registrar"))\n', "")
    # Handles BOTH import styles in one pass. The parenthesised multi-line
    # form is the one that silently half-matched before, leaving a dangling
    # "NotFound)" continuation line and an IndentationError.
    #   from passwordsafe import A, B  # comment
    #   from passwordsafe import (A, B,
    #                             C)
    src, n = re.subn(
        r"^from\s+passwordsafe\s+import\s+(?:\([^)]*\)|[^\n(]*)",
        "# --- inlined: registrar/passwordsafe.py ---",
        src, count=1, flags=re.M,
    )
    if n != 1:
        raise SystemExit(f"{name}: expected exactly one 'from passwordsafe "
                         f"import', matched {n}")

    src, cfg_literal = inline_config(src)

    marker = "# --- inlined: registrar/passwordsafe.py ---"
    if marker not in src:
        raise SystemExit(f"{name}: could not find the passwordsafe import to "
                         f"replace -- did the import style change?")

    src = src.replace(marker, marker + "\n\n" + lib + "\n" + cfg_literal
                      + "\n# --- end inlined library ---\n")

    # REPO no longer means anything in a standalone file
    src = src.replace(
        'REPO = pathlib.Path(__file__).resolve().parent.parent\n', "")

    # Stamp the build kind so the running tool announces which copy it is.
    # Two files called preflight.py on the same box is otherwise a coin toss.
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    src, n = re.subn(r'^BUILD_KIND = .*$',
                     f'BUILD_KIND = "STANDALONE, built {stamp}"',
                     src, count=1, flags=re.M)
    if n != 1 and "BUILD_KIND" in src:
        raise SystemExit(f"{name}: failed to stamp BUILD_KIND")

    DIST.mkdir(exist_ok=True)
    # Distinct filename: never collide with scripts/<name> in a shell history,
    # an scp, or a support ticket screenshot.
    out = DIST / name.replace(".py", "-standalone.py")
    out.write_text(BANNER.format(src=name) + src)
    out.chmod(0o755)
    return out


def main():
    built = []
    for name in TARGETS:
        if not (REPO / "scripts" / name).exists():
            print(f"skip {name} (not found)")
            continue
        out = build(name)

        # Compiling is not enough -- it accepts a file whose module-level code
        # raises NameError the instant it runs. EXECUTE the generated file
        # (via --help, which exits before touching the network) from a
        # directory with no repo in sight, exactly as an operator would.
        import py_compile
        import subprocess
        import tempfile
        try:
            py_compile.compile(str(out), doraise=True)
        except py_compile.PyCompileError as exc:
            raise SystemExit(f"generated {out.name} does not compile:\n{exc}")

        with tempfile.TemporaryDirectory() as elsewhere:
            proc = subprocess.run(
                [sys.executable, str(out), "--help"],
                cwd=elsewhere, capture_output=True, text=True,
            )
        if proc.returncode != 0:
            raise SystemExit(
                f"generated {out.name} compiles but fails to RUN:\n"
                f"{proc.stderr.strip()[-800:]}")

        built.append(out)
        print(f"built {out.relative_to(REPO)}  ({out.stat().st_size:,} bytes)"
              f"  [runs standalone]")

    if built:
        print("\nCopy anywhere and run -- no repo, no pip install:")
        print("  scp dist/preflight-standalone.py user@host:/tmp/")
        print("  PS_CLIENT_ID=... PS_CLIENT_SECRET=... \\")
        print("    python3 /tmp/preflight-standalone.py --team l1 --as onboarder")
        print("\nThese are snapshots. Rebuild after changing config/*.json or")
        print("registrar/passwordsafe.py, or you are testing stale settings.")
        print("Each one prints its build stamp on startup so you can tell.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
