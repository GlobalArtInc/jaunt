#!/usr/bin/env python3
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

TAG = re.compile(r"\d{14}-[0-9a-f]{7}")
TIMEOUT_SECS = 60
MAX_PAGES = 200


class PruneError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def select_stale(items, repository, name, keep):
    candidates = []
    for item in items:
        version = item.get("version")
        if item.get("repository") != repository or item.get("name") != name:
            continue
        if not isinstance(version, str) or TAG.fullmatch(version) is None:
            continue
        candidates.append((version, item))
    candidates.sort(key=lambda candidate: candidate[0], reverse=True)
    return [item for _, item in candidates[keep:]]


def call(url, auth, method="GET"):
    request = urllib.request.Request(url, method=method)
    request.add_header("Authorization", f"Basic {auth}")
    request.add_header("Accept", "application/json")
    with OPENER.open(request, timeout=TIMEOUT_SECS) as response:
        body = response.read()
        return json.loads(body) if body else None


def describe(err):
    if isinstance(err, urllib.error.HTTPError):
        return f"http status {err.code}"
    if isinstance(err, urllib.error.URLError):
        return f"connection failed ({type(err.reason).__name__})"
    return type(err).__name__


def list_components(base, auth, repository):
    items = []
    token = None
    seen = set()
    for _ in range(MAX_PAGES):
        query = {"repository": repository}
        if token:
            query["continuationToken"] = token
        page = call(f"{base}?{urllib.parse.urlencode(query)}", auth)
        items += page["items"]
        token = page.get("continuationToken")
        if not token:
            return items
        if token in seen:
            raise PruneError("the registry repeated a continuation token")
        seen.add(token)
    raise PruneError(f"the listing has more than {MAX_PAGES} pages")


def main():
    host = os.environ["ASTRUM_HOST"]
    repository = os.environ["ASTRUM_REPOSITORY"]
    name = os.environ["IMAGE_NAME"]
    keep = int(os.environ["KEEP"])
    dry_run = os.environ.get("DRY_RUN") == "1"
    if keep < 1:
        print("KEEP must be at least 1", file=sys.stderr)
        return 2
    credentials = f"{os.environ['ASTRUM_USERNAME']}:{os.environ['ASTRUM_PASSWORD']}"
    auth = base64.b64encode(credentials.encode()).decode()
    base = f"https://{host}/service/rest/v1/components"

    try:
        stale = select_stale(list_components(base, auth, repository), repository, name, keep)
    except PruneError as err:
        print(f"cannot list the components: {err}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError, KeyError, TypeError, json.JSONDecodeError) as err:
        print(f"cannot list the components: {describe(err)}", file=sys.stderr)
        return 1

    failed = 0
    for item in stale:
        label = f"{name}:{item['version']}"
        if dry_run:
            print(f"would remove {label}")
            continue
        try:
            call(f"{base}/{urllib.parse.quote(item['id'], safe='')}", auth, "DELETE")
            print(f"removed {label}")
        except (urllib.error.URLError, OSError, KeyError, TypeError, json.JSONDecodeError) as err:
            failed += 1
            print(f"could not remove {label}: {describe(err)}", file=sys.stderr)
    mode = "dry run, nothing deleted" if dry_run else f"failed: {failed}"
    print(f"stale: {len(stale)}; keep: {keep}; {mode}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
