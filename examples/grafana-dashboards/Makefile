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

current_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))


# setup grafana, prometheus and the charts
setup: setup-prometheus setup-grafana install-dashboards

# clean up the cluster
clean: clean-prometheus clean-grafana clean-dashboards

# install prometheus in the cluster
setup-prometheus: SCRAPE_INTERVAL ?= 30s
setup-prometheus:
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
	helm repo update
	helm upgrade prometheus prometheus-community/prometheus --install --wait \
	--namespace metrics --create-namespace \
	--set server.global.scrape_interval=$(SCRAPE_INTERVAL) $(HELM_ARGS)

clean-prometheus:
	helm uninstall prometheus --namespace=metrics

# install grafana in the cluster
setup-grafana: PASSWORD ?= admin
setup-grafana:
	helm repo add grafana https://grafana.github.io/helm-charts
	helm repo update
	helm upgrade grafana grafana/grafana --install --wait \
		--namespace=metrics --create-namespace \
		--set adminPassword=$(PASSWORD) $(HELM_ARGS) -f $(current_dir)/grafana.yaml

clean-grafana:
	helm uninstall grafana --namespace=metrics

install-dashboards:
	kubectl apply -f $(current_dir)/dashboards/

clean-dashboards:
	kubectl delete -f $(current_dir)/dashboards/

# portforward prometheus web ui
prometheus-portforward: DOCKER_RUN_ARGS+=--network=host
prometheus-portforward:
	kubectl port-forward deployments/prometheus-server 9090 -n metrics

# portforward grafana web ui
grafana-portforward: DOCKER_RUN_ARGS+=--network=host
grafana-portforward:
	kubectl port-forward deployments/grafana 3000 -n metrics
