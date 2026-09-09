from __future__ import annotations

import os
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import repo_sentinel_materialize as materializer  # noqa: E402
from repo_sentinel_reader import ReaderLimits, ReaderRefused  # noqa: E402


class MaterializationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory(prefix="materialization-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repository = self.root / "objects"
        self.repository.mkdir()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.git("init", "--bare", "--quiet")
        self.payload = b"raise RuntimeError('target must remain data')\n"
        blob = self.object("blob", self.payload)
        empty = self.object("blob", b"")
        child = self.object("tree", b"100755 trap.py\0" + bytes.fromhex(blob))
        tree = self.object("tree", b"100644 empty\0" + bytes.fromhex(empty)
                           + b"40000 nested\0" + bytes.fromhex(child))
        self.head = self.commit(tree)

    def git(self, *args: str, data: bytes | None = None) -> bytes:
        return subprocess.run(["git", *args], cwd=self.repository, input=data,
                              capture_output=True, check=True).stdout.strip()

    def object(self, kind: str, body: bytes) -> str:
        return self.git("hash-object", "--literally", "-w", "-t", kind,
                        "--stdin", data=body).decode()

    def commit(self, tree: str) -> str:
        return self.object("commit", (f"tree {tree}\n"
                           "author Fixture <fixture@example.com> 0 +0000\n"
                           "committer Fixture <fixture@example.com> 0 +0000\n\ntest\n").encode())

    def materialize(self):
        return materializer.materialized_snapshot(self.repository, self.head, self.scratch)

    def test_exact_files_are_yielded_as_data_then_removed(self) -> None:
        sentinel = self.scratch / "existing.txt"
        sentinel.write_bytes(b"keep unrelated scratch content")
        with self.materialize() as result:
            output = result.root
            self.assertEqual(result.snapshot.commit_oid, self.head)
            self.assertEqual((output / "empty").read_bytes(), b"")
            self.assertEqual((output / "nested/trap.py").read_bytes(), self.payload)
            self.assertEqual(result.snapshot.files[1].mode, "100755")
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE((output / "nested/trap.py").stat().st_mode), 0o600)
            self.assertNotIn(str(self.scratch), repr(result))
        self.assertFalse(output.exists())
        self.assertEqual(list(self.scratch.iterdir()), [sentinel])

    def test_consumer_exception_is_preserved_and_directory_is_removed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "consumer failed"):
            with self.materialize() as result:
                output = result.root
                raise RuntimeError("consumer failed")
        self.assertFalse(output.exists())
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_reader_refusal_creates_no_directory(self) -> None:
        with self.assertRaises(ReaderRefused):
            with materializer.materialized_snapshot(
                self.repository, self.head, self.scratch,
                limits=ReaderLimits(max_files=1),
            ):
                self.fail("refused input reached consumer")
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_unsafe_tree_path_cannot_escape_scratch(self) -> None:
        blob = self.object("blob", b"must not write")
        tree = self.object("tree", b"100644 ../escape\0" + bytes.fromhex(blob))
        with self.assertRaises(ReaderRefused):
            with materializer.materialized_snapshot(self.repository, self.commit(tree), self.scratch):
                self.fail("unsafe path reached consumer")
        self.assertFalse((self.root / "escape").exists())
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_write_failure_removes_partial_files_and_sanitizes_message(self) -> None:
        original = materializer._write_verified
        calls = 0

        def fail_second(path: Path, data: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("sensitive filesystem detail")
            original(path, data)

        with patch.object(materializer, "_write_verified", side_effect=fail_second):
            with self.assertRaisesRegex(materializer.MaterializationRefused,
                                        "^filesystem_io_failed$"):
                with self.materialize():
                    self.fail("partial files reached consumer")
        self.assertEqual(calls, 2)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_existing_entry_is_not_overwritten(self) -> None:
        original = materializer._write_verified

        def collide(path: Path, data: bytes) -> None:
            path.write_bytes(b"existing entry")
            try:
                original(path, data)
            finally:
                self.assertEqual(path.read_bytes(), b"existing entry")

        with patch.object(materializer, "_write_verified", side_effect=collide):
            with self.assertRaisesRegex(materializer.MaterializationRefused,
                                        "^filesystem_io_failed$"):
                with self.materialize():
                    self.fail("collision reached consumer")
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_readback_detects_same_length_corruption(self) -> None:
        original = materializer._regular_path

        def corrupt(path: Path, *, directory: bool = False) -> None:
            original(path, directory=directory)
            if not directory and path.name == "trap.py":
                path.write_bytes(b"X" * len(self.payload))

        with patch.object(materializer, "_regular_path", side_effect=corrupt):
            with self.assertRaisesRegex(materializer.MaterializationRefused,
                                        "^written_bytes_mismatch$"):
                with self.materialize():
                    self.fail("corrupted output reached consumer")
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_output_symlink_cannot_overwrite_an_external_file(self) -> None:
        sentinel = self.root / "sentinel"
        sentinel.write_bytes(b"external content")
        probe = self.root / "probe"
        try:
            probe.symlink_to(sentinel)
        except OSError:
            self.skipTest("file symlink creation unavailable")
        probe.unlink()
        original = materializer._write_verified

        def inject_link(path: Path, data: bytes) -> None:
            path.symlink_to(sentinel)
            original(path, data)

        with patch.object(materializer, "_write_verified", side_effect=inject_link):
            with self.assertRaisesRegex(materializer.MaterializationRefused,
                                        "^filesystem_io_failed$"):
                with self.materialize():
                    self.fail("output symlink reached consumer")
        self.assertEqual(sentinel.read_bytes(), b"external content")
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_cleanup_failure_is_explicit(self) -> None:
        created = []

        def fail_cleanup() -> None:
            raise OSError("local path")

        def capture(**kwargs):
            temporary = TemporaryDirectory(**kwargs)
            created.append(temporary)
            self.addCleanup(temporary.cleanup)
            return temporary

        with patch.object(materializer, "TemporaryDirectory", side_effect=capture):
            with self.assertRaisesRegex(materializer.MaterializationRefused, "^cleanup_failed$"):
                with self.materialize():
                    created[0].cleanup = fail_cleanup

    def test_empty_tree_has_a_valid_temporary_lifecycle(self) -> None:
        head = self.commit(self.object("tree", b""))
        with materializer.materialized_snapshot(self.repository, head, self.scratch) as result:
            self.assertEqual(result.snapshot.files, ())
            self.assertEqual(list(result.root.iterdir()), [])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_scratch_symlink_is_refused_without_touching_target(self) -> None:
        alias = self.root / "alias"
        try:
            alias.symlink_to(self.scratch, target_is_directory=True)
        except OSError:
            self.skipTest("directory symlink creation unavailable")
        with self.assertRaisesRegex(materializer.MaterializationRefused,
                                    "^unsafe_filesystem_entry$"):
            with materializer.materialized_snapshot(self.repository, self.head, alias):
                self.fail("symlink scratch reached consumer")
        self.assertEqual(list(self.scratch.iterdir()), [])
        self.assertTrue(alias.is_symlink())

    def test_missing_scratch_is_refused_without_creating_it(self) -> None:
        missing = self.root / "missing"
        with self.assertRaisesRegex(materializer.MaterializationRefused,
                                    "^filesystem_io_failed$"):
            with materializer.materialized_snapshot(self.repository, self.head, missing):
                self.fail("missing scratch reached consumer")
        self.assertFalse(missing.exists())


if __name__ == "__main__":
    unittest.main()
