# iperf3 Performance Test

This example uses [iperf3](https://iperf.fr/) to perform a performance test on Quilkin instance to look at throughput, 
jitter and packet loss.

## Requirements

* Release version of Quilkin
* A bash terminal
* socat
* iperf3
* wget

## run.sh

This bash script sets up an iperf3 server, a Quilkin proxy with no filters, and an iperf3 client that sends data for 60 
seconds.

Several files are captured during the process:

* client.log - output from the iperf3 client.
* metrics.json - a copy of the Quilkin prometheus metrics on test completion.
* quilkin.log - output from Quilkin.
* server.log - output from the iperf3 server.
* socat.log - output from the socat tcp tunnel (usually empty).

## clean.sh

If run.sh fails for any reason, it could leave behind orphaned processes. This script will clean them up, as well as 
any log files that are a result of the test. 
