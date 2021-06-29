# Continuous integration build image management

This is cloud build script that is rerun nightly to ensure that the build images we use for CI and releases are always 
up to date.

This `cloudbuild.yaml` assumes there is a container repository called `ci` already created in your project.

To create this, run: `gcloud artifacts repositories create ci --repository-format=docker --location=us`.