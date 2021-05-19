// Copyright 2021 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

module github-bot

go 1.16

require (
	github.com/GoogleCloudPlatform/cloud-build-notifiers/lib/notifiers v0.0.0-20210219212036-163c92a64b27
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/google/go-github/v35 v35.2.0
	golang.org/x/oauth2 v0.0.0-20210201163806-010130855d6c
	golang.org/x/tools v0.1.1 // indirect
	google.golang.org/genproto v0.0.0-20210513213006-bf773b8c8384
)
