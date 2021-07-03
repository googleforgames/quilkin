# Build Release

Run `make` to submit the `cloudbuild.yaml` to [Google Cloud Build](https://cloud.google.com/build) and build the 
release:

* Linux, Windows and macOS executable for both release and debug.
* Docker images for both release and debug.

If you need to pass extra arguments to the `make` target, the target comes with an `$(ARGS)` parameter than can be
used.

The executables are stored under `gs://$PROJECT_ID-quilkin-releases` in a zip file named quilkin-${version}.zip, 
where the version is the version stored in Cargo.toml.

This `cloudbuild.yaml` assumes several things are set up in the project:

## Docker container repository

There needs to be a docker container repository called `release` already created in your 
project, and the release images will create the Docker images therein. The images will be tagged with both ${version} 
and ${version}-debug where the version is the version stored in Cargo.toml.

The ${version}-debug tagged version runs the debug binary of Quilkin, where the ${version} tag runs the production 
release binary.

To create this, run: `gcloud artifacts repositories create release --repository-format=docker --location=us`.

## Github Developer Token

The release process generates a CHANGELOG.md. To do this, Cloud Build needs access to GitHub's API.

To do this we need to enable [Secret Manager](https://cloud.google.com/secret-manager) with the requisite GitHub
credentials.

Create a GitHub [Personal access token](https://github.com/settings/tokens) with the ability to access the public 
repository.

Use the [Creating and accessing secrets](https://cloud.google.com/secret-manager/docs/creating-and-accessing-secrets)
guide to create a secret named `release-github-token` with the GitHub token previously generated. 

Finally, follow [Using secrets from Secret Manager](https://cloud.google.com/build/docs/securing-builds/use-secrets) 
guide to enable Secret Manager in Cloud Build.
