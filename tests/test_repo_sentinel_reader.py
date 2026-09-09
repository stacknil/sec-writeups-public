from __future__ import annotations

import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from repo_sentinel_reader import ReaderLimits, ReaderRefused, read_snapshot  # noqa: E402


class ReaderTests(unittest.TestCase):
    def repository(self, algorithm: str = "sha1") -> Path:
        temporary = TemporaryDirectory(prefix="reader-contract-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.git(root, "init", "--bare", "--quiet", f"--object-format={algorithm}")
        return root

    def git(self, root: Path, *args: str, data: bytes | None = None) -> bytes:
        return subprocess.run(["git", *args], cwd=root, input=data,
                              capture_output=True, check=True).stdout.strip()

    def object(self, root: Path, kind: str, body: bytes) -> str:
        return self.git(root, "hash-object", "--literally", "-t", kind,
                        "-w", "--stdin", data=body).decode()

    def tree(self, root: Path, entries: list[tuple[bytes, bytes, str]]) -> str:
        raw = b"".join(mode + b" " + name + b"\0" + bytes.fromhex(oid)
                       for mode, name, oid in entries)
        return self.object(root, "tree", raw)

    def commit(self, root: Path, tree: str) -> str:
        body = (f"tree {tree}\nauthor Fixture <fixture@example.com> 0 +0000\n"
                "committer Fixture <fixture@example.com> 0 +0000\n\nfixture\n")
        return self.object(root, "commit", body.encode())

    def fixture(self, algorithm: str = "sha1") -> tuple[Path, str, str]:
        root = self.repository(algorithm)
        blob = self.object(root, "blob", b"original\0bytes\r\n")
        tree = self.tree(root, [(b"100644", b"evidence.bin", blob)])
        return root, self.commit(root, tree), blob

    def test_raw_bytes_modes_nested_paths_and_both_object_formats(self) -> None:
        for algorithm in ("sha1", "sha256"):
            with self.subTest(algorithm=algorithm):
                root, _, blob = self.fixture(algorithm)
                child = self.tree(root, [(b"100755", b"trap.py", blob)])
                attrs = self.object(root, "blob", b"* export-ignore\n* export-subst\n")
                tree = self.tree(root, [(b"40000", b"nested", child),
                                        (b"100644", b".gitattributes", attrs)])
                head = self.commit(root, tree)
                result = read_snapshot(root, head)
                self.assertEqual((result.commit_oid, result.tree_oid), (head, tree))
                self.assertEqual([item.path for item in result.files],
                                 [".gitattributes", "nested/trap.py"])
                self.assertEqual(result.files[1].mode, "100755")
                self.assertEqual(result.files[1].data, b"original\0bytes\r\n")
                self.assertNotIn("original", repr(result))
                self.assertFalse((root / "nested").exists())

    def test_replacement_refs_do_not_change_snapshot(self) -> None:
        root, head, blob = self.fixture()
        expected = read_snapshot(root, head)
        replacement = self.object(root, "blob", b"replacement")
        self.git(root, "replace", blob, replacement)
        self.assertEqual(read_snapshot(root, head), expected)

    def test_wrong_type_and_missing_objects_are_refused(self) -> None:
        root, head, blob = self.fixture()
        for oid in (blob, "0" * 40, "HEAD", head[:12], "-v"):
            with self.subTest(oid=oid), self.assertRaises(ReaderRefused):
                read_snapshot(root, oid)

    def test_nonregular_modes_and_type_mismatch_are_refused(self) -> None:
        root, head, blob = self.fixture()
        for mode, oid in ((b"120000", blob), (b"160000", head),
                          (b"100644", head), (b"40000", blob)):
            tree = self.tree(root, [(mode, b"entry", oid)])
            with self.subTest(mode=mode), self.assertRaises(ReaderRefused):
                read_snapshot(root, self.commit(root, tree))

    def test_unsafe_paths_and_case_collisions_are_refused(self) -> None:
        root, _, blob = self.fixture()
        for name in (b"..", b".GiT", b"a/b", b"a\\b", b"NUL.txt", b"LPT1",
                     b"NUL .txt", b"COM1  .log", b"x.", b"x ", b"a:b",
                     b"a\nb", b"a\tb", b"\xff"):
            with self.subTest(name=name):
                tree = self.tree(root, [(b"100644", name, blob)])
                with self.assertRaisesRegex(ReaderRefused, "^unsupported_path$"):
                    read_snapshot(root, self.commit(root, tree))
        child = self.tree(root, [(b"100644", b"child", blob)])
        tree = self.tree(root, [(b"40000", b"Dir", child),
                                (b"100644", b"dir", blob)])
        with self.assertRaisesRegex(ReaderRefused, "^path_collision$"):
            read_snapshot(root, self.commit(root, tree))

    def test_limits_refuse_instead_of_returning_a_partial_snapshot(self) -> None:
        root, head, blob = self.fixture()
        two = self.tree(root, [(b"100644", b"a", blob), (b"100644", b"b", blob)])
        head = self.commit(root, two)
        cases = (("max_files", 1, "file_limit"), ("max_objects", 2, "object_limit"),
                 ("max_bytes", 1, "byte_limit"), ("max_blob_bytes", 1, "byte_limit"))
        for field, limit, code in cases:
            with self.subTest(field=field), self.assertRaisesRegex(ReaderRefused, code):
                read_snapshot(root, head, limits=replace(ReaderLimits(), **{field: limit}))
        nested = self.tree(root, [(b"40000", b"d", two)])
        nested = self.tree(root, [(b"40000", b"d", nested)])
        with self.assertRaisesRegex(ReaderRefused, "depth_limit"):
            read_snapshot(root, self.commit(root, nested), limits=ReaderLimits(max_depth=1))

    def test_exact_byte_budget_accepts_and_one_less_refuses(self) -> None:
        root, head, blob = self.fixture()
        tree = read_snapshot(root, head).tree_oid
        size = sum(int(self.git(root, "cat-file", "-s", oid)) for oid in (head, tree, blob))
        result = read_snapshot(root, head, limits=ReaderLimits(max_bytes=size))
        self.assertEqual(len(result.files), 1)
        with self.assertRaisesRegex(ReaderRefused, "byte_limit"):
            read_snapshot(root, head, limits=ReaderLimits(max_bytes=size - 1))

    def test_truncated_tree_is_refused(self) -> None:
        root = self.repository()
        tree = self.object(root, "tree", b"100644 bad\0\x01")
        with self.assertRaisesRegex(ReaderRefused, "invalid_tree"):
            read_snapshot(root, self.commit(root, tree))

    def test_object_rehash_rejects_corrupted_transport_bytes(self) -> None:
        root, head, _ = self.fixture()
        import repo_sentinel_reader as reader
        original = reader._git

        def corrupt(repository: Path, args: list[str], cap: int, deadline: float) -> bytes:
            data = original(repository, args, cap, deadline)
            return data + b"changed" if args[:2] == ["cat-file", "blob"] else data

        with patch.object(reader, "_git", side_effect=corrupt):
            with self.assertRaisesRegex(ReaderRefused, "object_identity_mismatch"):
                read_snapshot(root, head)

    def test_deadline_kills_a_stalled_git_child(self) -> None:
        root, head, _ = self.fixture()
        original = subprocess.Popen

        def stalled(*args: object, **kwargs: object) -> subprocess.Popen:
            return original([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)

        with patch("repo_sentinel_reader.subprocess.Popen", side_effect=stalled):
            with self.assertRaisesRegex(ReaderRefused, "time_limit"):
                read_snapshot(root, head, limits=ReaderLimits(timeout_seconds=0.1))

    def test_invalid_limits_are_refused(self) -> None:
        for value in (0, -1, float("nan"), float("inf"), True, "30", None):
            with self.subTest(value=value), self.assertRaises(ReaderRefused):
                ReaderLimits(timeout_seconds=value)
        with self.assertRaises(ReaderRefused):
            ReaderLimits(max_depth=65)


if __name__ == "__main__":
    unittest.main()
