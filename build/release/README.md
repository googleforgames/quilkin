# Build Release

Run `make` to submit the `cloudbuild.yaml` to [Google Cloud Build](https://cloud.google.com/build) and build the 
release:

* Linux executable for both release and debug.
* Windows executable for both release and debug.

The executables are stored under `gs://$PROJECT_ID-quilkin-releases` in a zip file named quilkin-${version}.zip, 
where the version is the version stored in Cargo.toml.

If you need to pass extra arguments to the `make` target, the target comes with an `$(ARGS)` parameter than can be
used.