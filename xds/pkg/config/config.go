/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"encoding/json"
	"fmt"

	envoylistener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"quilkin.dev/xds-management-server/pkg/cluster"
)

type Json struct {
	Clusters    []cluster.Cluster `json:"clusters"`
	Filters     []Filter          `json:"filters"`
}

type Filter struct {
	Name   string                  `json:"name"`
	Config *map[string]interface{} `json:"config"`
}

type Config struct {
	Clusters    []cluster.Cluster
	FilterChain *envoylistener.FilterChain
}

func FromJsonString(str string) (*Config, error) {
	var encoded *Json
	config := &Config{}
	err := json.Unmarshal([]byte(str), &encoded)

	config.Clusters = encoded.Clusters

	if err != nil {
		return nil, err
	}

	if encoded != nil && encoded.Filters != nil {
        chain, err := FilterChainFromJson(encoded.Filters)

        if err != nil {
            return nil, err
        }

        config.FilterChain = chain
    }

	return config, nil
}

func FilterChainFromJson(filters []Filter) (*envoylistener.FilterChain, error) {
	envoyFilters := []*envoylistener.Filter{}

    for _, filter := range filters {
        var filter_instance *envoylistener.Filter
        if filter.Config != nil {
            value, err := structpb.NewStruct(*filter.Config)

            if err != nil {
                return nil, err
            }

            instance, err := CreateXdsFilter(filter.Name, value)

            if err != nil {
                return nil, err
            }

            filter_instance = instance
        } else {
            instance, err := CreateXdsFilter(filter.Name, structpb.NewNullValue())

            if err != nil {
                return nil, err
            }

            filter_instance = instance
        }

        envoyFilters = append(envoyFilters, filter_instance)
    }

    return &envoylistener.FilterChain{
        Filters: envoyFilters,
    }, nil
}

// createXdsFilter creates an xds filter with the provided proto.
func CreateXdsFilter(name string, filter proto.Message) (*envoylistener.Filter, error) {
    value, err := proto.Marshal(filter)

	if err != nil {
		return nil, fmt.Errorf("failed to marshal %s filter to protobuf: %w", name, err)
	}

	any := &anypb.Any{
        TypeUrl: name,
        Value: value,
    }

	return &envoylistener.Filter{
		Name: name,
		ConfigType: &envoylistener.Filter_TypedConfig{
			TypedConfig: any,
		},
	}, nil
}
