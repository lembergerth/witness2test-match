#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
import os
import subprocess
import tempfile
import unittest
import zipfile


class ArchiveIntegrationTest(unittest.TestCase):
    def test_archive_layout_and_smoketest(self):
        root = Path(__file__).resolve().parent
        version_output = subprocess.check_output(
            [str(root / "bin/witness2test-match"), "--version"], text=True
        )
        version = version_output.strip().split()[-1]
        archive = root / f"witness2test-match-{version}.zip"
        expected_paths = {
            "bin/",
            "bin/witness2test-match",
            "smoketest.sh",
            "integration-test.sh",
            "REUSE.toml",
            "LICENSE",
            "README.adoc",
        }
        for directory in ("integration", "LICENSES"):
            expected_paths.add(f"{directory}/")
            for path in (root / directory).rglob("*"):
                expected_paths.add(
                    path.relative_to(root).as_posix() + ("/" if path.is_dir() else "")
                )

        expected_members = {f"{archive.stem}/{path}" for path in expected_paths}
        expected_members.add(f"{archive.stem}/")
        with zipfile.ZipFile(archive) as package:
            self.assertCountEqual(package.namelist(), expected_members)
            self.assertIsNone(package.testzip())

        with tempfile.TemporaryDirectory(prefix="witness2test-archive-") as extraction_dir:
            subprocess.run(
                ["unzip", "-q", str(archive)], cwd=extraction_dir, check=True
            )
            extraction = Path(extraction_dir)
            self.assertEqual(
                {path.name for path in extraction.iterdir()}, {archive.stem}
            )
            release = extraction / archive.stem
            for path in sorted(expected_paths):
                if not path.endswith("/"):
                    with self.subTest(path=path):
                        self.assertEqual(
                            (release / path).read_bytes(), (root / path).read_bytes()
                        )
            for path in ("bin/witness2test-match", "smoketest.sh", "integration-test.sh"):
                with self.subTest(executable=path):
                    self.assertTrue(os.access(release / path, os.X_OK), path)
            self.assertEqual(
                subprocess.check_output(
                    [str(release / "bin/witness2test-match"), "--version"], text=True
                ),
                version_output,
            )
            verdict_files = sorted((root / "integration").glob("*/expected-verdict"))
            self.assertTrue(verdict_files, "No integration fixtures found")
            expected_smoke_output = "".join(
                f"PASS: {path.parent.name} ({path.read_text().strip()})\n"
                for path in verdict_files
            ) + f"\nSummary: {len(verdict_files)} passed, 0 failed\n"
            self.assertEqual(
                subprocess.check_output(
                    [str(release / "smoketest.sh")],
                    cwd=extraction,
                    text=True,
                    timeout=60,
                ),
                expected_smoke_output,
            )


if __name__ == "__main__":
    unittest.main()
