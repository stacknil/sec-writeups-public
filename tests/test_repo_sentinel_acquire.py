from __future__ import annotations

import subprocess
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import repo_sentinel_acquire as acquisition  # noqa: E402
from repo_sentinel_reader import ReaderLimits, ReaderRefused  # noqa: E402


class AcquisitionTests(unittest.TestCase):
    def repository(self, algorithm: str = "sha1") -> tuple[Path, Path]:
        temporary = TemporaryDirectory(prefix="acquisition-contract-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        remote = root / "remote.git"
        scratch = root / "scratch"
        scratch.mkdir()
        self.git(root, "init", "--bare", "--quiet", f"--object-format={algorithm}", remote)
        return remote, scratch

    def git(
        self, root: Path, *args: str | Path, data: bytes | None = None
    ) -> bytes:
        return subprocess.run(
            ["git", *(str(arg) for arg in args)],
            cwd=root,
            input=data,
            capture_output=True,
            check=True,
        ).stdout.strip()

    def object(self, remote: Path, kind: str, body: bytes) -> str:
        return self.git(
            remote, "hash-object", "--literally", "-w", "-t", kind, "--stdin", data=body
        ).decode()

    def tree(self, remote: Path, entries: list[tuple[bytes, bytes, str]]) -> str:
        raw = b"".join(
            mode + b" " + name + b"\0" + bytes.fromhex(oid)
            for mode, name, oid in entries
        )
        return self.object(remote, "tree", raw)

    def commit(self, remote: Path, tree: str, label: str = "fixture") -> str:
        body = (
            f"tree {tree}\nauthor Fixture <fixture@example.com> 0 +0000\n"
            f"committer Fixture <fixture@example.com> 0 +0000\n\n{label}\n"
        )
        return self.object(remote, "commit", body.encode())

    def fixture(self, algorithm: str = "sha1") -> tuple[Path, Path, str]:
        remote, scratch = self.repository(algorithm)
        trap = self.object(remote, "blob", b"raise RuntimeError('must remain data')\n")
        evidence = self.object(remote, "blob", b"evidence\0bytes\r\n")
        child = self.tree(remote, [(b"100755", b"trap.py", trap)])
        tree = self.tree(
            remote,
            [(b"100644", b"evidence.bin", evidence), (b"40000", b"nested", child)],
        )
        head = self.commit(remote, tree)
        self.git(remote, "update-ref", "refs/pull/7/head", head)
        return remote, scratch, head

    def acquire(
        self,
        remote: Path,
        scratch: Path,
        head: str,
        **kwargs: object,
    ):
        return acquisition.acquire_pull_snapshot(remote, 7, head, scratch, **kwargs)

    def test_exact_head_is_read_as_data_in_both_object_formats(self) -> None:
        for algorithm in ("sha1", "sha256"):
            with self.subTest(algorithm=algorithm):
                remote, scratch, head = self.fixture(algorithm)
                marker = scratch.parent / "target-ran"
                with self.acquire(remote, scratch, head) as result:
                    database = result.repository
                    self.assertTrue(database.is_dir())
                    self.assertEqual(result.source_ref, "refs/pull/7/head")
                    self.assertEqual(result.snapshot.commit_oid, head)
                    self.assertEqual(
                        [item.path for item in result.snapshot.files],
                        ["evidence.bin", "nested/trap.py"],
                    )
                    self.assertEqual(result.snapshot.files[0].data, b"evidence\0bytes\r\n")
                    refs = self.git(
                        database, "for-each-ref", "--format=%(refname)", "refs/"
                    ).decode()
                    self.assertEqual(refs, "refs/repo-sentinel/acquired-head")
                    self.assertNotIn(str(scratch), repr(result))
                    self.assertFalse(marker.exists())
                self.assertFalse(database.exists())
                self.assertEqual(list(scratch.iterdir()), [])

    def test_unrequested_refs_are_not_imported(self) -> None:
        remote, scratch, head = self.fixture()
        extra = self.commit(remote, self.tree(remote, []), "unrequested")
        self.git(remote, "update-ref", "refs/heads/unrequested", extra)
        self.git(remote, "update-ref", "refs/tags/unrequested", extra)
        with self.acquire(remote, scratch, head) as result:
            refs = self.git(
                result.repository, "for-each-ref", "--format=%(refname)", "refs/"
            ).decode()
            self.assertEqual(refs, "refs/repo-sentinel/acquired-head")
            objects = self.git(
                result.repository, "cat-file", "--batch-check", data=(extra + "\n").encode()
            )
            self.assertEqual(objects.decode(), f"{extra} missing")

    def test_moved_ref_and_wrong_expected_head_are_refused(self) -> None:
        remote, scratch, original = self.fixture()
        moved = self.commit(remote, self.tree(remote, []), "moved")
        self.git(remote, "update-ref", "refs/pull/7/head", moved)
        with self.assertRaisesRegex(acquisition.AcquisitionRefused, "^head_mismatch$"):
            with self.acquire(remote, scratch, original):
                self.fail("moved ref reached the reader")
        self.assertEqual(list(scratch.iterdir()), [])

    def test_missing_pull_ref_is_a_sanitized_fetch_refusal(self) -> None:
        remote, scratch, head = self.fixture()
        with self.assertRaisesRegex(acquisition.AcquisitionRefused, "^fetch_failed$"):
            with acquisition.acquire_pull_snapshot(remote, 8, head, scratch):
                self.fail("missing ref reached the reader")
        self.assertEqual(list(scratch.iterdir()), [])

    def test_reader_refusal_creates_no_surviving_database(self) -> None:
        remote, scratch, head = self.fixture()
        with self.assertRaises(ReaderRefused):
            with self.acquire(
                remote, scratch, head, reader_limits=ReaderLimits(max_files=1)
            ):
                self.fail("incomplete snapshot reached the consumer")
        self.assertEqual(list(scratch.iterdir()), [])

    def test_unsupported_fetched_path_preserves_reader_refusal(self) -> None:
        remote, scratch, _ = self.fixture()
        blob = self.object(remote, "blob", b"data")
        tree = self.tree(remote, [(b"100644", b"Command & Carol.md", blob)])
        head = self.commit(remote, tree, "unsupported path")
        self.git(remote, "update-ref", "refs/pull/7/head", head)
        with self.assertRaisesRegex(ReaderRefused, "^unsupported_path$"):
            with self.acquire(remote, scratch, head):
                self.fail("reader refusal became a successful acquisition")
        self.assertEqual(list(scratch.iterdir()), [])

    def test_repository_byte_limit_refuses_and_cleans_up(self) -> None:
        remote, scratch, head = self.fixture()
        limits = acquisition.AcquisitionLimits(max_repository_bytes=1)
        with self.assertRaisesRegex(
            acquisition.AcquisitionRefused, "^repository_byte_limit$"
        ):
            with self.acquire(remote, scratch, head, acquisition_limits=limits):
                self.fail("over-budget database reached the reader")
        self.assertEqual(list(scratch.iterdir()), [])

    def test_timeout_kills_fetch_and_cleans_up(self) -> None:
        remote, scratch, head = self.fixture()
        original = subprocess.Popen

        def stall_fetch(args: list[str], **kwargs: object) -> subprocess.Popen:
            if "fetch" in args:
                args = [sys.executable, "-c", "import time; time.sleep(30)"]
            return original(args, **kwargs)

        started = time.monotonic()
        with patch("repo_sentinel_acquire.subprocess.Popen", side_effect=stall_fetch):
            with self.assertRaisesRegex(acquisition.AcquisitionRefused, "^time_limit$"):
                with self.acquire(
                    remote,
                    scratch,
                    head,
                    acquisition_limits=acquisition.AcquisitionLimits(timeout_seconds=0.1),
                ):
                    self.fail("timed-out fetch reached the reader")
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(list(scratch.iterdir()), [])

    def test_consumer_exception_is_preserved_and_database_is_removed(self) -> None:
        remote, scratch, head = self.fixture()
        with self.assertRaisesRegex(RuntimeError, "consumer failed"):
            with self.acquire(remote, scratch, head) as result:
                database = result.repository
                raise RuntimeError("consumer failed")
        self.assertFalse(database.exists())
        self.assertEqual(list(scratch.iterdir()), [])

    def test_invalid_identifiers_and_remote_forms_are_refused(self) -> None:
        remote, scratch, head = self.fixture()
        for number in (0, -1, True, "7", 2_147_483_648):
            with self.subTest(number=number), self.assertRaisesRegex(
                acquisition.AcquisitionRefused, "^invalid_pull_number$"
            ):
                with acquisition.acquire_pull_snapshot(remote, number, head, scratch):
                    self.fail("invalid pull number reached Git")
        for oid in (head.upper(), head[:12], "HEAD", "0" * 41, "-" * len(head)):
            with self.subTest(oid=oid), self.assertRaisesRegex(
                acquisition.AcquisitionRefused, "^invalid_head_oid$"
            ):
                with acquisition.acquire_pull_snapshot(remote, 7, oid, scratch):
                    self.fail("invalid OID reached Git")
        for value in (
            "http://example.com/repo.git",
            "ssh://example.com/repo.git",
            "https://user:secret@example.com/repo.git",
            "https://example.com/repo.git?ref=x",
            "https://example.com/repo.git#fragment",
            "https://example.com/repo git",
            "-upload-pack=trap",
        ):
            with self.subTest(remote=value), self.assertRaisesRegex(
                acquisition.AcquisitionRefused, "^invalid_remote$"
            ):
                with acquisition.acquire_pull_snapshot(value, 7, head, scratch):
                    self.fail("invalid remote reached Git")

    def test_scratch_symlink_is_refused_without_touching_target(self) -> None:
        remote, scratch, head = self.fixture()
        alias = scratch.parent / "alias"
        try:
            alias.symlink_to(scratch, target_is_directory=True)
        except OSError:
            self.skipTest("directory symlink creation unavailable")
        with self.assertRaisesRegex(
            acquisition.AcquisitionRefused, "^unsafe_scratch_root$"
        ):
            with self.acquire(remote, alias, head):
                self.fail("scratch alias reached Git")
        self.assertEqual(list(scratch.iterdir()), [])

    def test_invalid_limits_are_refused(self) -> None:
        for value in (0, -1, float("nan"), float("inf"), True, "60", None):
            with self.subTest(value=value), self.assertRaisesRegex(
                acquisition.AcquisitionRefused, "^invalid_limits$"
            ):
                acquisition.AcquisitionLimits(timeout_seconds=value)
        with self.assertRaisesRegex(acquisition.AcquisitionRefused, "^invalid_limits$"):
            acquisition.AcquisitionLimits(max_repository_bytes=True)


if __name__ == "__main__":
    unittest.main()
