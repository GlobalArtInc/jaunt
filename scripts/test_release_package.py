import hashlib
import importlib.util
import os
import tarfile
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "release-package.py")
SPEC = importlib.util.spec_from_file_location("release_package", SCRIPT)
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)

TARGET = "x86_64-unknown-linux-musl"


class Workspace:
    def __init__(self, test):
        self.directory = tempfile.TemporaryDirectory()
        test.addCleanup(self.directory.cleanup)
        self.root = self.directory.name
        self.license = self.write("LICENSE", b"license text\n")
        self.agent = self.write("bin/jaunt-agent", b"\x7fELF agent")
        self.cli = self.write("bin/jaunt", b"\x7fELF cli")
        self.helper = self.write("bin/jaunt-host-users", b"\x7fELF helper")

    def write(self, name, data):
        path = os.path.join(self.root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def run(self, out, *binaries, version="1.2.3", target=TARGET, epoch="1700000000"):
        return packager.main(
            [
                "--version", version,
                "--target", target,
                "--epoch", epoch,
                "--license", self.license,
                "--out", os.path.join(self.root, out),
                *binaries,
            ]
        )

    def read(self, out, name):
        with open(os.path.join(self.root, out, name), "rb") as handle:
            return handle.read()


class Package(unittest.TestCase):
    def test_archive_has_the_binary_license_and_readme_with_fixed_metadata(self):
        space = Workspace(self)
        space.run("out", space.agent)
        archive = os.path.join(space.root, "out", f"jaunt-agent-1.2.3-{TARGET}.tar.gz")
        with tarfile.open(archive) as handle:
            members = {member.name: member for member in handle.getmembers()}
            self.assertEqual(
                sorted(members),
                sorted(
                    [
                        f"jaunt-agent-1.2.3-{TARGET}",
                        f"jaunt-agent-1.2.3-{TARGET}/jaunt-agent",
                        f"jaunt-agent-1.2.3-{TARGET}/LICENSE",
                        f"jaunt-agent-1.2.3-{TARGET}/README.txt",
                    ]
                ),
            )
            binary = members[f"jaunt-agent-1.2.3-{TARGET}/jaunt-agent"]
            self.assertEqual(binary.mode, 0o755)
            for member in members.values():
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 1700000000))
            readme = handle.extractfile(f"jaunt-agent-1.2.3-{TARGET}/README.txt").read().decode()
            self.assertIn("Statically linked", readme)

    def test_same_input_gives_identical_bytes_and_a_matching_checksum_line(self):
        space = Workspace(self)
        space.run("first", space.agent, space.cli)
        space.run("second", space.agent, space.cli)
        name = f"jaunt-1.2.3-{TARGET}.tar.gz"
        first = space.read("first", name)
        self.assertEqual(first, space.read("second", name))
        sums = space.read("first", f"SHA256SUMS.{TARGET}").decode().splitlines()
        self.assertIn(f"{hashlib.sha256(first).hexdigest()}  {name}", sums)
        self.assertEqual(len(sums), 2)

    def test_the_account_helper_gets_its_own_archive_named_like_the_others(self):
        space = Workspace(self)
        space.run("out", space.agent, space.helper)
        name = f"jaunt-host-users-1.2.3-{TARGET}.tar.gz"
        with tarfile.open(os.path.join(space.root, "out", name)) as handle:
            members = {member.name: member for member in handle.getmembers()}
            self.assertEqual(
                sorted(members),
                sorted(
                    [
                        f"jaunt-host-users-1.2.3-{TARGET}",
                        f"jaunt-host-users-1.2.3-{TARGET}/jaunt-host-users",
                        f"jaunt-host-users-1.2.3-{TARGET}/LICENSE",
                        f"jaunt-host-users-1.2.3-{TARGET}/README.txt",
                    ]
                ),
            )
            self.assertEqual(members[f"jaunt-host-users-1.2.3-{TARGET}/jaunt-host-users"].mode, 0o755)
        sums = space.read("out", f"SHA256SUMS.{TARGET}").decode().splitlines()
        digest = hashlib.sha256(space.read("out", name)).hexdigest()
        self.assertIn(f"{digest}  {name}", sums)
        self.assertEqual(len(sums), 2)

    def test_macos_archive_does_not_claim_static_linking(self):
        space = Workspace(self)
        space.run("out", space.cli, target="aarch64-apple-darwin")
        archive = os.path.join(space.root, "out", "jaunt-1.2.3-aarch64-apple-darwin.tar.gz")
        with tarfile.open(archive) as handle:
            readme = handle.extractfile("jaunt-1.2.3-aarch64-apple-darwin/README.txt").read().decode()
        self.assertNotIn("Statically", readme)


class Rejects(unittest.TestCase):
    def test_bad_arguments_exit_with_an_error(self):
        space = Workspace(self)
        cases = [
            {"version": "../1"},
            {"version": ""},
            {"target": "linux"},
            {"epoch": "-1"},
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(SystemExit):
                space.run("out", space.agent, **case)

    def test_unknown_binary_name_is_refused(self):
        space = Workspace(self)
        stranger = space.write("bin/other", b"x")
        with self.assertRaises(ValueError):
            space.run("out", stranger)


if __name__ == "__main__":
    unittest.main()
