#!/usr/bin/env bash

#
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

set -eo pipefail

CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"

# Need to grabs source for MPL, GPL, LGPL, and CDDL licenced dependencies
# and include it in the Docker image

# This should be reviewed before each release to make sure we're capturing all
# the dependencies we need.

dependencies=(webpki-roots)

zip="$(pwd)/dependencies-src.zip"

rm "$zip" || true

echo "Archiving dependencies to: $zip"

# create an empty zip, so we always have a file, even if we don't have dependencies
echo UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA== | base64 -d > "$zip"

pushd "$CARGO_HOME/registry/src"
for d in "${dependencies[@]}"; do
  find . -type d -name "$d-*" | xargs -I {} zip -ruv "$zip" "{}"
done
popd
