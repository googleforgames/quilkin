# How to Contribute

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines you need to follow.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution,
this simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.developers.google.com/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Code of Conduct

Participation in this project comes under the [Contributor Covenant Code of Conduct](code-of-conduct.md)

## Submitting code via Pull Requests

- We follow the [GitHub Pull Request Model](https://help.github.com/articles/about-pull-requests/) for
  all contributions.
- For large bodies of work, we recommend creating an issue and labelling it
  "[kind/design](https://github.com/googleforgames/quilkin/issues?q=is%3Aissue+is%3Aopen+label%3Akind%2Fdesign)"
  outlining the feature that you wish to build, and describing how it will be implemented. This gives a chance
  for review to happen early, and ensures no wasted effort occurs.
- For new features, documentation *must* be included. Documentation can currently be found under 
  the [docs](./docs) folder.
- All submissions, including submissions by project members, will require review before being merged.
- Finally - *Thanks* for considering submitting code to Quilkin!

## Development

We welcome development from the community on Quilkin!

### Cloning the repository

We use several submodules, so make sure you have them downloaded and updated.

```shell script
git clone https://github.com/googleforgames/quilkin.git
cd quilkin
git submodule update --init --recursive
```

You will likely want to replace `https://github.com/googleforgames/quilkin.git` with your own fork of the repository
for your development.

### Building

Debug release:

`cargo build`

Production Release:

`cargo build --release`

### Testing

We use some nightly features to automatically test our external documentation, so you will need to be explicit about
which tests you wish to run.

To run the unit and integration tests:

`cargo test --tests`

To run our external documentation tests:

`cargo +nightly test --doc`

## Coding standards

When submitting pull requests, make sure to do the following:

- Format all Rust code with [rustfmt](https://github.com/rust-lang/rustfmt).
- Ensure all Rust code passes the Rust [clippy](https://github.com/rust-lang/rust-clippy) linter.
- Remove trailing whitespace. Many editors will do this automatically.
- Ensure any new files have [a trailing newline](https://stackoverflow.com/questions/5813311/no-newline-at-end-of-file)

## Continuous Integration

Continuous integration is provided by [Google Cloud Build](https://cloud.google.com/cloud-build),
through the [cloudbuild.yaml](./cloudbuild.yaml) file found at the root of the directory, and integrated with the
Github repository via the 
[Cloud Build Github app](https://cloud.google.com/cloud-build/docs/automating-builds/run-builds-on-github).

Build success or failure are displayed on each pull request with relevant details.

To gain access to the details of a specific Cloud Build, join the 
[quilkin-discuss](https://groups.google.com/forum/#!forum/quilkin-discuss) google group.

See the [Google Cloud Build documentation](https://cloud.google.com/cloud-build/docs/) for more details on
how to edit and expand the build process.

## Releases

* At the monthly community meeting it will be decided if a release should be built.
* To release, create an issue from the [release issue template](./build/templates/release-issue.md), tag it as
  `kind/release` and follow each of the steps.

### Additional Resources

#### Coding and Development

- [How to write a good Git Commit message](https://chris.beams.io/posts/git-commit/) -
  Great way to make sure your Pull Requests get accepted.
