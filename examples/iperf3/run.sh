#!/usr/bin/env bash
#
# Copyright 2021 Google LLC All Rights Reserved.
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
set +x

path=$(dirname "$0")

QUILKIN_PATH="${QUILKIN_PATH:-$path/../../target/release/quilkin}"
CONFIG="${CONFIG:-$path/proxy.yaml}"
PARALLEL="${PARALLEL:-50}"
BANDWIDTH="${BANDWIDTH:-3M}"

# This tunnel is needed because iperf3 requires a tcp handshake before starting the UDP load test
echo "Starting socat tcp tunnel..."
socat tcp-listen:8000,reuseaddr,fork tcp:localhost:8001 > socat.log &
echo "Starting iperf3 server..."
iperf3 -s -p 8001 > server.log &
echo "Starting quilkin server..."
"$QUILKIN_PATH" -f "$CONFIG" > quilkin.log &

echo "Waiting for startup..."
# Wait for both processes to start up.
sleep 5

echo "Running iperf3 client..."

set -x
iperf3 --client 127.0.0.1 --port 8000 --parallel $PARALLEL --bidir --bandwidth $BANDWIDTH --time 60 --udp | tee client.log
set +x

echo "Taking a snapshot of Quilkin metrics..."
wget -O metrics.json http://localhost:9091/metrics

kill -SIGTERM %3
kill -SIGTERM %2
kill -SIGTERM %1

echo "Perf test complete!"
