# Release process

A release is built by `.github/workflows/release.yml`. It publishes the archives described in [install.md](install.md) with a `SHA256SUMS` file and a build provenance attestation for every archive and for `SHA256SUMS`.

## How to cut a release

- Tag a commit that is on `main` with `v<major>.<minor>.<patch>` (a suffix such as `-rc.1` makes it a pre-release) and push the tag. The workflow builds, checks the archives on the target distributions and publishes the release.
- Or run the workflow by hand from `main`. The version defaults to the Cargo version plus the short commit. The result is a draft unless `publish` is set. The tag `v<version>` must not exist yet. Runs from other branches build and check the archives but create no release.
- If the arm64 runner is not available, run the workflow by hand with `include_arm` off. The Linux aarch64 archives are then left out and the release holds five archives instead of eight.

The release is always created as a draft, every file is uploaded, and only then is it published (when it is a tag run or `publish` is set). A failed run therefore never leaves a published release with missing files. When a run starts and a draft release for the same tag exists from an earlier run, it is deleted and created again. A release that is already published is never replaced: the run fails, and a new version is needed.

## Repository settings the workflow relies on

The checks in the workflow (the tag must point to a commit on `main`) are not the only control. Set up:

- A tag ruleset for `v*` that allows creating tags only to maintainers and forbids updating and deleting them.
- An environment `release` with required reviewers and a deployment policy limited to `main` and the `v*` tags. The release job runs in this environment, so nothing is published without an approval.
- Workflow permissions of the repository set to read by default; the release job asks for `contents: write`, `id-token: write` and `attestations: write` itself.

## Checks in CI

The `release-scripts` job in `ci.yml` runs `actionlint` over the workflows, `shellcheck` over the release scripts and the unit tests of the packaging and planning scripts.
