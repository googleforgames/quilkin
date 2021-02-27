# Build Release

Run `make` to submit the `cloudbuild.yaml` to [Google Cloud Build](https://cloud.google.com/build) and build the 
release:

* Linux executable for both release and debug.
* Windows executable for both release and debug.
* Docker images for both release and debug.

The executables are stored under `gs://$PROJECT_ID-quilkin-releases` in a zip file named quilkin-${version}.zip, 
where the version is the version stored in Cargo.toml.

This `cloudbuild.yaml` assumes there is a docker container repository called `release` already created in your 
project, and will create the Docker images therein. The images will be tagged with both ${version} and ${version}-debug 
where the version is the version stored in Cargo.toml.

The ${version}-debug tagged version runs the debug binary of Quilkin, where the ${version} tag runs the production 
release binary.

To create this, run: `gcloud artifacts repositories create release --repository-format=docker --location=us`.

If you need to pass extra arguments to the `make` target, the target comes with an `$(ARGS)` parameter than can be
used.
