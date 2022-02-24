# Copyright 2021 Google LLC
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

ARG PROFILE

FROM gcr.io/distroless/cc:nonroot as base
WORKDIR /
COPY ./license.html .
COPY ./dependencies-src.zip .
COPY --chown=nonroot:nonroot ./image/quilkin.yaml /etc/quilkin/quilkin.yaml

FROM base as release
COPY ./target/x86_64-unknown-linux-gnu/release/quilkin .

FROM base as debug
COPY ./target/x86_64-unknown-linux-gnu/debug/quilkin .

FROM $PROFILE
USER nonroot:nonroot
ENTRYPOINT ["/quilkin", "--config", "/etc/quilkin/quilkin.yaml", "run"]
