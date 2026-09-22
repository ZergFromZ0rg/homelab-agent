"""The Dockerfile copies its modules in by name, so a new one is silently
left out of the image and the agent dies on import at startup. That
happened once (connections.py); this makes it fail here instead.
"""

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def local_modules() -> set[str]:
    """Top-level .py files in the repo that aren't tests or config."""
    return {
        path.stem
        for path in ROOT.glob("*.py")
        if path.stem not in ("conftest",)
    }


def imported_by(module: str) -> set[str]:
    tree = ast.parse((ROOT / f"{module}.py").read_text())
    names = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])

    return names


def _logical_lines(text: str) -> list[str]:
    """Dockerfile lines with backslash continuations joined up.

    The COPY grew past one readable line once there were a dozen modules,
    and a line-at-a-time reader silently sees only the first few — which
    reports modules that *are* in the image as missing.
    """
    lines, current = [], ""

    for raw in text.splitlines():
        stripped = raw.strip()

        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
            continue

        lines.append((current + stripped).strip())
        current = ""

    if current:
        lines.append(current.strip())

    return lines


def copied_into_image() -> set[str]:
    for line in _logical_lines((ROOT / "Dockerfile").read_text()):
        if line.startswith("COPY") and ".py" in line:
            return {
                token[:-3]
                for token in line.split()
                if token.endswith(".py")
            }
    raise AssertionError("no COPY line for .py files in the Dockerfile")


def test_every_module_the_app_imports_is_in_the_image():
    copied = copied_into_image()
    local = local_modules()

    # Everything main.py pulls in from this repo, transitively.
    needed, seen = set(), {"main"}
    queue = ["main"]
    while queue:
        module = queue.pop()
        for name in imported_by(module):
            if name in local and name not in seen:
                seen.add(name)
                needed.add(name)
                queue.append(name)

    missing = (needed | {"main"}) - copied
    assert not missing, f"not COPYed into the image: {sorted(missing)}"
