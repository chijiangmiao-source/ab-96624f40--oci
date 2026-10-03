"""Whiteout-rule tests for the union engine."""

import unittest

from app.engine import EngineError, apply_layers
from app.tarparse import TYPE_DIR, TYPE_FILE, TYPE_LINK, Entry


def F(path):
    return Entry(path, TYPE_FILE, 1)


def D(path):
    return Entry(path, TYPE_DIR)


def L(path, target):
    return Entry(path, TYPE_LINK, 0, target)


def paths_of(result):
    return {item["path"]: item for item in result["paths"]}


class WhiteoutTests(unittest.TestCase):
    def test_whiteout_deletes_lower_file_and_leaves_no_trace(self):
        result = apply_layers([
            [D("etc"), F("etc/cal.txt"), F("etc/keep.txt")],
            [F("etc/.wh.cal.txt")],
        ])
        paths = paths_of(result)
        self.assertEqual(sorted(paths), ["etc", "etc/keep.txt"])
        self.assertEqual(paths["etc/keep.txt"]["layer"], 0)
        self.assertEqual(result["deletions"], [{
            "path": "etc/cal.txt", "layer": 0, "kind": "whiteout",
            "byLayer": 1, "via": "etc/.wh.cal.txt",
        }])

    def test_whiteout_removes_whole_subtree(self):
        result = apply_layers([
            [D("a"), D("a/b"), F("a/b/c.txt"), F("a/top.txt")],
            [F("a/.wh.b")],
        ])
        self.assertEqual(sorted(paths_of(result)), ["a", "a/top.txt"])
        self.assertEqual(
            [d["path"] for d in result["deletions"]], ["a/b", "a/b/c.txt"])

    def test_whiteout_of_missing_path_is_tolerated(self):
        result = apply_layers([[F("x.txt")], [F(".wh.never-existed")]])
        self.assertEqual(sorted(paths_of(result)), ["x.txt"])
        self.assertEqual(result["deletions"], [])

    def test_opaque_clears_lower_children_but_keeps_same_layer_entries(self):
        result = apply_layers([
            [D("d"), F("d/old1.txt"), F("d/old2.txt"), D("d/sub"),
             F("d/sub/deep.txt"), F("top.txt")],
            [F("d/.wh..wh..opq"), F("d/new.txt")],
        ])
        paths = paths_of(result)
        self.assertEqual(sorted(paths), ["d", "d/new.txt", "top.txt"])
        self.assertEqual(paths["d"]["layer"], 0)  # dir itself survives
        self.assertEqual(paths["d/new.txt"]["layer"], 1)
        kinds = {d["path"]: d["kind"] for d in result["deletions"]}
        self.assertEqual(kinds, {
            "d/old1.txt": "opaque",
            "d/old2.txt": "opaque",
            "d/sub": "opaque",
            "d/sub/deep.txt": "opaque",
        })

    def test_opaque_marker_added_after_new_entries_still_preserves_them(self):
        result = apply_layers([
            [D("d"), F("d/old.txt")],
            [F("d/fresh.txt"), F("d/.wh..wh..opq")],
        ])
        self.assertEqual(sorted(paths_of(result)), ["d", "d/fresh.txt"])

    def test_opaque_at_root_clears_all_lower_layers(self):
        result = apply_layers([
            [F("a.txt"), D("d"), F("d/b.txt")],
            [F(".wh..wh..opq"), F("c.txt")],
        ])
        self.assertEqual(sorted(paths_of(result)), ["c.txt"])

    def test_rebuild_after_whiteout(self):
        result = apply_layers([
            [F("cfg.txt")],
            [F(".wh.cfg.txt")],
            [F("cfg.txt")],
        ])
        paths = paths_of(result)
        self.assertEqual(paths["cfg.txt"]["layer"], 2)
        self.assertEqual(len(result["deletions"]), 1)
        self.assertEqual(result["deletions"][0]["kind"], "whiteout")

    def test_file_replaces_dir_and_drops_descendants(self):
        result = apply_layers([
            [D("p"), F("p/child.txt")],
            [F("p")],
        ])
        paths = paths_of(result)
        self.assertEqual(paths["p"]["type"], "file")
        self.assertEqual(paths["p"]["layer"], 1)
        self.assertEqual(
            {d["path"] for d in result["deletions"]}, {"p", "p/child.txt"})
        self.assertTrue(all(d["kind"] == "replaced" for d in result["deletions"]))

    def test_dir_replaces_file(self):
        result = apply_layers([
            [F("p")],
            [D("p"), F("p/child.txt")],
        ])
        paths = paths_of(result)
        self.assertEqual(paths["p"]["type"], "dir")
        self.assertEqual(paths["p"]["layer"], 1)
        self.assertEqual(paths["p/child.txt"]["layer"], 1)
        self.assertEqual([d["path"] for d in result["deletions"]], ["p"])

    def test_dir_restatement_keeps_lower_source_layer(self):
        result = apply_layers([
            [D("d"), F("d/a.txt")],
            [D("d"), F("d/b.txt")],
        ])
        paths = paths_of(result)
        self.assertEqual(paths["d"]["layer"], 0)
        self.assertEqual(paths["d/b.txt"]["layer"], 1)
        self.assertEqual(result["deletions"], [])

    def test_file_superseded_by_later_file_records_evidence(self):
        result = apply_layers([[F("m.txt")], [F("m.txt")]])
        self.assertEqual(paths_of(result)["m.txt"]["layer"], 1)
        self.assertEqual(result["deletions"], [{
            "path": "m.txt", "layer": 0, "kind": "replaced",
            "byLayer": 1, "via": "m.txt",
        }])

    def test_hardlink_within_layer(self):
        result = apply_layers([[F("a.txt"), L("b.txt", "a.txt")]])
        paths = paths_of(result)
        self.assertEqual(paths["b.txt"]["type"], "file")
        self.assertEqual(paths["b.txt"]["link"], "a.txt")

    def test_hardlink_to_lower_layer_is_dangling(self):
        with self.assertRaises(EngineError):
            apply_layers([[F("a.txt")], [L("b.txt", "a.txt")]])

    def test_hardlink_to_missing_target_is_dangling(self):
        with self.assertRaises(EngineError):
            apply_layers([[L("b.txt", "missing.txt")]])

    def test_hardlink_to_directory_rejected(self):
        with self.assertRaises(EngineError):
            apply_layers([[D("dir"), L("b.txt", "dir")]])

    def test_hardlink_to_whiteout_deleted_file_is_dangling(self):
        with self.assertRaises(EngineError):
            apply_layers([[F("a.txt"), F(".wh.a.txt"), L("b.txt", "a.txt")]])

    def test_duplicate_entry_rejected(self):
        with self.assertRaises(EngineError):
            apply_layers([[F("a.txt"), F("a.txt")]])

    def test_delete_and_recreate_in_same_layer_is_duplicate(self):
        with self.assertRaises(EngineError):
            apply_layers([[F("a.txt"), F(".wh.a.txt"), F("a.txt")]])

    def test_parent_file_conflict_rejected(self):
        with self.assertRaises(EngineError):
            apply_layers([[F("a"), F("a/b.txt")]])

    def test_failed_layer_aborts_whole_audit(self):
        # Second layer is invalid; apply_layers must raise and hand back
        # nothing (the caller discards the private tree).
        with self.assertRaises(EngineError) as ctx:
            apply_layers([[F("ok.txt")], [F("x"), F("x/y.txt")]])
        self.assertIn("layer 1", str(ctx.exception))

    def test_implicit_parent_dirs_get_current_layer(self):
        result = apply_layers([[F("a/b/c.txt")]])
        paths = paths_of(result)
        self.assertEqual(paths["a"]["type"], "dir")
        self.assertEqual(paths["a"]["layer"], 0)
        self.assertEqual(paths["a/b"]["layer"], 0)


if __name__ == "__main__":
    unittest.main()
