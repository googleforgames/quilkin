# Release {version}

## Prerequisites

- [ ] Have at least `Editor` level access to `quilkin` Google Cloud project.
- [ ] Local git remote `upstream` points at `git@github.com:googleforgames/quilkin.git`.

## Steps

- [ ] Review that closed issues have appropriate tags for the changelog.
- [ ] Review that merged PRs have appropriate tags for the changelog.
- [ ] Run `git remote update && git checkout main && git reset --hard upstream/main` to ensure your code is in line
  with upstream.
- [ ] Update Cargo version for release
    - [ ] Edit the `version` field in `./Cargo.toml` and remove the `-dev` suffix.
    - [ ] Edit the `quilkin-macros` dependency in `./Cargo.toml` and remove the `-dev` suffix.
    - [ ] Edit the `version` field in `./macros/Cargo.toml` and remove the `-dev` suffix.
- [ ] cd to `./build/release` and run `make` to submit the cloud build
- [ ] Download all the artifacts from the cloud build.
- [ ] Move the CHANGELOG.md to the root of this repository, replacing any previous versions.
- [ ] Review `license.html` to ensure that there aren't any new MPL, GPL, LGPL, or CDDL dependencies from the last 
  release. If there are:
    - [ ] Add the dependencies to
    [archive_dependencies.sh](https://github.com/googleforgames/quilkin/blob/main/build/release/archive_dependencies.sh) 
    so that the source is archived in the container image.
    - [ ] Reset checklist back to "run `make` to submit the cloud build", and start from there again.
- [ ] Run `cd macros && cargo publish --dry-run` and ensure there are no issues.
- [ ] Run `cargo publish --dry-run` and ensure there are no issues.  
- [ ] Submit these changes as a PR, and merge with approval.
- [ ] Create a [Github release](https://github.com/googleforgames/quilkin/releases/new) using the 
  [Github release template](./github-release.md).
    - [ ] Populate the tag with `v{version}`, description, and relevant changelog sections.
    - [ ] Attach all the remaining cloud build artifacts to the release.
- [ ] Run `git remote update && git checkout main && git reset --hard upstream/main` to ensure your code is in line
      with upstream.
- [ ] Run `git checkout -b release-{version} && git push upstream` to create a release branch.
- [ ] Publish to [crates.io/crates/quilkin-macros](https://crates.io/crates/quilkin-macros): run `cd macros && cargo publish`
- [ ] Publish to [crates.io/crates/quilkin](https://crates.io/crates/quilkin): run `cargo publish`
- [ ] Submit the release.
- [ ] Post an announcement to the [mailing list](https://groups.google.com/g/quilkin-discuss).
- [ ] Post to the [Twitter account](https://twitter.com/quilkindev).
- [ ] Update Cargo version for development
    - [ ] Edit `Cargo.toml` and increment the [minor version](https://semver.org/) and apply the `-dev` suffix to the
       `version`.
    - [ ] Edit the `quilkin-macros` dependency in `./Cargo.toml` and increment the [minor version](https://semver.org/) 
       and apply the `-dev` suffix to the `version`.
    - [ ] Edit the `version` field in `./macros/Cargo.toml`and increment the [minor version](https://semver.org/)
       and apply the `-dev` suffix to the `version`.
- [ ] Submit this change as a PR, and merge with approval.

Congratulation! 🎉 You have successfully released Quilkin!
