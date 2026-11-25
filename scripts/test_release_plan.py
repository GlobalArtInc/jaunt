import os
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "release-plan.sh")
SHA = "0123456789abcdef0123456789abcdef01234567"
KEYS = [
    "version",
    "tag",
    "draft",
    "prerelease",
    "release",
    "archives",
    "build_matrix",
    "verify_matrix",
]


class Plan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.manifest = os.path.join(cls.directory.name, "Cargo.toml")
        with open(cls.manifest, "w") as handle:
            handle.write('[workspace]\nmembers = []\n\n[workspace.package]\nversion = "1.4.0"\nedition = "2024"\n')

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_plan(self, **overrides):
        env = {
            "PATH": os.environ["PATH"],
            "EVENT": "workflow_dispatch",
            "REF": "refs/heads/main",
            "REF_NAME": "main",
            "SHA": SHA,
            "RELEASE_PLAN_CARGO_TOML": self.manifest,
            "RELEASE_PLAN_ON_MAIN": "true",
            "RELEASE_PLAN_TAG_EXISTS": "false",
        }
        env.update(overrides)
        result = subprocess.run(
            ["bash", SCRIPT], env=env, capture_output=True, text=True, check=False
        )
        return result

    def plan(self, **overrides):
        result = self.run_plan(**overrides)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual([line.split("=", 1)[0] for line in lines], KEYS)
        return dict(line.split("=", 1) for line in lines)

    def refuses(self, **overrides):
        result = self.run_plan(**overrides)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")
        self.assertIn("error:", result.stderr)

    def test_dispatch_from_main_defaults_to_a_draft_with_the_cargo_version_and_short_sha(self):
        plan = self.plan()
        self.assertEqual(plan["version"], "1.4.0-0123456")
        self.assertEqual(plan["tag"], "v1.4.0-0123456")
        self.assertEqual(plan["draft"], "true")
        self.assertEqual(plan["release"], "true")
        self.assertEqual(plan["prerelease"], "true")
        self.assertEqual(plan["archives"], "8")

    def test_dispatch_publish_true_is_not_a_draft_and_a_plain_version_is_not_a_prerelease(self):
        plan = self.plan(INPUT_VERSION="2.0.0", INPUT_PUBLISH="true")
        self.assertEqual((plan["draft"], plan["prerelease"], plan["tag"]), ("false", "false", "v2.0.0"))

    def test_dispatch_from_another_branch_builds_but_does_not_release(self):
        plan = self.plan(REF="refs/heads/feature", REF_NAME="feature", RELEASE_PLAN_TAG_EXISTS="true")
        self.assertEqual(plan["release"], "false")

    def test_dispatch_refuses_a_version_whose_tag_already_exists(self):
        self.refuses(INPUT_VERSION="2.0.0", RELEASE_PLAN_TAG_EXISTS="true")

    def test_tag_push_on_main_is_published_after_the_upload(self):
        plan = self.plan(EVENT="push", REF="refs/tags/v3.1.4", REF_NAME="v3.1.4", RELEASE_PLAN_TAG_EXISTS="true")
        self.assertEqual(
            (plan["version"], plan["tag"], plan["release"], plan["draft"]),
            ("3.1.4", "v3.1.4", "true", "false"),
        )

    def test_tag_push_off_main_is_refused(self):
        self.refuses(EVENT="push", REF="refs/tags/v3.1.4", REF_NAME="v3.1.4", RELEASE_PLAN_ON_MAIN="false")

    def test_push_that_is_not_a_tag_or_has_a_mismatched_name_is_refused(self):
        self.refuses(EVENT="push", REF="refs/heads/main", REF_NAME="main")
        self.refuses(EVENT="push", REF="refs/tags/v3.1.4", REF_NAME="v9.9.9")
        self.refuses(EVENT="push", REF="refs/tags/3.1.4", REF_NAME="3.1.4")

    def test_include_arm_false_drops_the_arm_linux_entries(self):
        plan = self.plan(INPUT_INCLUDE_ARM="false")
        self.assertEqual(plan["archives"], "5")
        self.assertNotIn("aarch64-unknown-linux-musl", plan["build_matrix"])
        self.assertNotIn("aarch64", plan["verify_matrix"])
        self.assertIn("aarch64-apple-darwin", plan["build_matrix"])

    def test_tag_push_ignores_include_arm(self):
        plan = self.plan(EVENT="push", REF="refs/tags/v3.1.4", REF_NAME="v3.1.4", INPUT_INCLUDE_ARM="false")
        self.assertEqual(plan["archives"], "8")

    def test_hostile_versions_are_refused_and_print_nothing(self):
        hostile = [
            "1.0\nversion=9.9.9\ntag=main",
            "1.0.0\nversion=9.9.9",
            "1.0.0\r",
            "1.0.0 ",
            " 1.0.0",
            "1.0.0 beta",
            "1.0.0$(id)",
            "1.0.0`id`",
            "1.0.0;rm",
            "../1.0.0",
            "1.0.0/../x",
            "v1.0.0",
            "1.0",
            "1",
            "main",
            "1.0.0-",
            "1.0.0-a" + "b" * 80,
        ]
        for version in hostile:
            with self.subTest(version=version):
                self.refuses(INPUT_VERSION=version)

    def test_valid_versions_are_accepted(self):
        for version in ["0.0.1", "10.20.30", "1.0.0-rc.1", "1.0.0+build.5", "1.0.0-rc.1+meta"]:
            with self.subTest(version=version):
                self.assertEqual(self.plan(INPUT_VERSION=version)["version"], version)

    def test_hostile_tag_names_on_push_are_refused(self):
        for name in ["v1.0.0\nversion=9.9.9", "v1.0.0 x", "v../1.0.0", "v1.0.0$(id)"]:
            with self.subTest(name=name):
                self.refuses(EVENT="push", REF="refs/tags/" + name, REF_NAME=name)

    def test_bad_flags_sha_and_event_are_refused(self):
        self.refuses(INPUT_PUBLISH="yes")
        self.refuses(INPUT_INCLUDE_ARM="maybe")
        self.refuses(SHA="abc")
        self.refuses(SHA=SHA.upper())
        self.refuses(SHA=SHA + "\nx=1")
        self.refuses(EVENT="pull_request")


if __name__ == "__main__":
    unittest.main()
