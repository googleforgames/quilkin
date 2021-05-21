# Google Cloud Builder Custom CI Step

Running `make` will submit and build the custom
[Google Cloud Builder](https://cloud.google.com/build/docs/configuring-builds/use-community-and-custom-builders#creating_a_custom_builder) 
step that is used for this project, and push the image to 
[Google Cloud Artifact Registry](https://cloud.google.com/artifact-registry), via the `cloudbuild.yaml` in this folder.

This `cloudbuild.yaml` assumes there is a container repository called `ci` already created in your project.

To create this, run: `gcloud artifacts repositories create ci --repository-format=docker --location=us`.

If you need to pass extra arguments to the `make` target, the target comes with an `$(ARGS)` parameter that can be 
used.
