"""Union file tree with OCI whiteout (".wh.") semantics.

Layers are applied bottom-to-top onto a per-audit tree.  Any failure aborts
the whole audit: the tree is built privately and only handed back on full
success, so a failed layer can never leave a partial adjudication behind.

Rules implemented:

* ``.wh.<name>`` removes ``<name>`` (and its subtree) from lower layers;
  the whiteout entry itself never appears in the result.
* ``.wh..wh..opq`` marks the containing directory opaque: every descendant
  coming from lower layers is removed, while entries added by the current
  layer survive.
* A regular entry replaces a lower entry of a different type (file vs dir);
  replacing a directory drops its whole subtree.  Re-stating a directory
  keeps its original (lower) source layer.
* Hard links must resolve to a regular file that appeared earlier in the
  same layer and still exists in the tree (no dangling links).
* Duplicate canonical paths within one layer are rejected.
"""

from __future__ import annotations

from dataclasses import dataclass

from .tarparse import Entry, TYPE_DIR, TYPE_LINK

OPAQUE_MARKER = ".wh..wh..opq"
WHITEOUT_PREFIX = ".wh."


class EngineError(ValueError):
    """Raised when a layer cannot be applied to the union tree."""


@dataclass
class Node:
    type: str  # "file" | "dir"
    layer: int  # source layer index (0 = bottom layer)
    link: str | None = None  # hard-link target, if created by a link entry


def _parent(path: str) -> str:
    idx = path.rfind("/")
    return path[:idx] if idx != -1 else ""


def _ensure_dir(tree: dict[str, Node], path: str, layer: int) -> None:
    """Materialize ``path`` (and missing ancestors) as directories."""
    if not path:
        return
    parts = path.split("/")
    for k in range(1, len(parts) + 1):
        prefix = "/".join(parts[:k])
        node = tree.get(prefix)
        if node is None:
            tree[prefix] = Node("dir", layer)
        elif node.type != "dir":
            raise EngineError(f"parent {prefix!r} is not a directory")


def _drop_subtree(tree: dict[str, Node], root: str, kind: str,
                  by_layer: int, via: str, deletions: list[dict]) -> None:
    """Remove ``root`` and its descendants, recording deletion evidence."""
    victims = sorted(p for p in tree if p == root or p.startswith(root + "/"))
    for path in victims:
        node = tree.pop(path)
        deletions.append({
            "path": path,
            "layer": node.layer,
            "kind": kind,
            "byLayer": by_layer,
            "via": via,
        })


def _apply_one(tree: dict[str, Node], deletions: list[dict],
               index: int, entries: list[Entry]) -> None:
    seen: set[str] = set()
    linkables: set[str] = set()  # file/link entries earlier in this layer
    for entry in entries:
        if entry.path in seen:
            raise EngineError(f"duplicate entry {entry.path!r} in layer")
        seen.add(entry.path)
        base = entry.path.rsplit("/", 1)[-1]
        parent = _parent(entry.path)

        if base == OPAQUE_MARKER:
            _ensure_dir(tree, parent, index)
            prefix = parent + "/" if parent else ""
            for path in sorted(list(tree)):
                node = tree[path]
                if path != parent and path.startswith(prefix) and node.layer < index:
                    del tree[path]
                    deletions.append({
                        "path": path,
                        "layer": node.layer,
                        "kind": "opaque",
                        "byLayer": index,
                        "via": entry.path,
                    })
            continue

        if base.startswith(WHITEOUT_PREFIX):
            name = base[len(WHITEOUT_PREFIX):]
            if not name:
                raise EngineError(f"invalid whiteout entry {entry.path!r}")
            _ensure_dir(tree, parent, index)
            target = parent + "/" + name if parent else name
            # Deleting a path absent from the union is a tolerated no-op.
            _drop_subtree(tree, target, "whiteout", index, entry.path, deletions)
            continue

        _ensure_dir(tree, parent, index)
        ntype = "dir" if entry.type == TYPE_DIR else "file"
        existing = tree.get(entry.path)
        if existing is not None and not (existing.type == "dir" and ntype == "dir"):
            # File/dir replacement (either direction) or file superseded:
            # the lower content is removed and recorded as evidence.
            _drop_subtree(tree, entry.path, "replaced", index, entry.path, deletions)
            existing = None
        if existing is None:
            tree[entry.path] = Node(
                ntype, index, entry.link if entry.type == TYPE_LINK else None)

        if entry.type == TYPE_LINK:
            if entry.link not in linkables:
                raise EngineError(
                    f"hard link {entry.path!r} target {entry.link!r} "
                    "not present earlier in the same layer")
            target = tree.get(entry.link)
            if target is None or target.type != "file":
                raise EngineError(
                    f"hard link {entry.path!r} has dangling target {entry.link!r}")
        if ntype == "file":
            linkables.add(entry.path)


def apply_layers(layers: list[list[Entry]]) -> dict:
    """Apply validated layers bottom-to-top; return the frozen adjudication."""
    tree: dict[str, Node] = {}
    deletions: list[dict] = []
    for index, entries in enumerate(layers):
        try:
            _apply_one(tree, deletions, index, entries)
        except EngineError as exc:
            raise EngineError(f"layer {index}: {exc}") from exc
    paths = []
    for path in sorted(tree):
        node = tree[path]
        item = {"path": path, "type": node.type, "layer": node.layer}
        if node.link is not None:
            item["link"] = node.link
        paths.append(item)
    deletions.sort(key=lambda d: (d["byLayer"], d["path"]))
    return {"paths": paths, "deletions": deletions}
