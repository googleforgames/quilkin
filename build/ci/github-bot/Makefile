# Copyright 2021 Google LLC All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

STORAGE := gs://quilkin-ci-config

current_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

all: build deploy

# build: creates the project Cloud Build custom build step and hosts it on gcr.io
build:
	gcloud builds submit . --config=cloudbuild.yaml $(ARGS)

# deploy pushes a new version to Cloud Run
deploy:
	-gsutil mb $(STORAGE)
	gsutil cp $(current_dir)/github.yaml $(STORAGE)
	gcloud run deploy github-bot \
		--image="us-docker.pkg.dev/quilkin/ci/github-bot" \
		--platform managed \
		--no-allow-unauthenticated \
		--region=us-west3 \
		--update-env-vars="CONFIG_PATH=$(STORAGE)/github.yaml"
