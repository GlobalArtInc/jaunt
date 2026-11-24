import importlib.util
import os
import unittest
import urllib.request

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "astrum-prune.py")
SPEC = importlib.util.spec_from_file_location("astrum_prune", SCRIPT)
prune = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prune)

REPOSITORY = "docker-prod"
NAME = "jaunt"


def item(version, repository=REPOSITORY, name=NAME):
    return {"id": f"id-{version}", "repository": repository, "name": name, "version": version}


def stale_versions(items, keep):
    return [entry["version"] for entry in prune.select_stale(items, REPOSITORY, NAME, keep)]


class SelectStale(unittest.TestCase):
    def test_keeps_the_newest_by_timestamp_and_returns_the_rest(self):
        items = [
            item("20260101000000-aaaaaaa"),
            item("20260103000000-ccccccc"),
            item("20260102000000-bbbbbbb"),
        ]
        self.assertEqual(
            stale_versions(items, 2),
            ["20260101000000-aaaaaaa"],
        )

    def test_nothing_is_stale_within_the_keep_count(self):
        items = [item("20260101000000-aaaaaaa"), item("20260102000000-bbbbbbb")]
        self.assertEqual(stale_versions(items, 2), [])
        self.assertEqual(stale_versions(items, 5), [])

    def test_only_exact_timestamp_and_short_hash_tags_are_candidates(self):
        foreign = [
            item("latest"),
            item("api-20260101000000-aaaaaaa"),
            item("20260101000000-aaaaaaa-extra"),
            item("20260101000000-AAAAAAA"),
            item("20260101000000-aaaaaa"),
            item("2026010100000-aaaaaaa"),
            item("20260101000000-aaaaaaaa"),
            {"id": "x", "repository": REPOSITORY, "name": NAME},
            item(None),
        ]
        self.assertEqual(stale_versions(foreign + [item("20260102000000-bbbbbbb")], 1), [])

    def test_other_repositories_and_images_are_never_selected(self):
        items = [
            item("20260101000000-aaaaaaa"),
            item("20260102000000-bbbbbbb", repository="docker-dev"),
            item("20260103000000-ccccccc", name="other"),
            {"id": "y", "version": "20260104000000-ddddddd"},
        ]
        self.assertEqual(stale_versions(items, 1), [])

    def test_no_components_selects_nothing(self):
        self.assertEqual(stale_versions([], 1), [])


class Redirects(unittest.TestCase):
    def test_a_redirect_is_not_followed(self):
        handler = prune.NoRedirect()
        request = urllib.request.Request("https://registry.example/x")
        self.assertIsNone(
            handler.redirect_request(request, None, 302, "Found", {}, "http://elsewhere.example/")
        )


if __name__ == "__main__":
    unittest.main()
