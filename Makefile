# Copyright 2017 The Kubernetes Authors.
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

.PHONY: all
all: all-container

BUILDTAGS=

# Use the 0.0 tag for testing, it shouldn't clobber any release builds
TAG?=0.1.0
REGISTRY?=quay.io/easywp
GOOS?=linux
DOCKER?=gcloud docker --
SED_I?=sed -i
GOHOSTOS ?= $(shell go env GOHOSTOS)

ifeq ($(GOHOSTOS),darwin)
  SED_I=sed -i ''
endif

REPO_INFO=$(shell git config --get remote.origin.url)

ifndef COMMIT
  COMMIT := git-$(shell git rev-parse --short HEAD)
endif

PKG=github.com/NCCloud/fluid

ARCH ?= $(shell go env GOARCH)
GOARCH = ${ARCH}
DUMB_ARCH = ${ARCH}

QEMUVERSION=v2.9.1-1

IMGNAME = fluid
IMAGE = $(REGISTRY)/$(IMGNAME)

TEMP_DIR := $(shell mktemp -d)

DOCKERFILE := $(TEMP_DIR)/rootfs/Dockerfile

.PHONY: image-info
image-info:
	echo -n '{"image":"$(IMAGE)","tag":"$(TAG)"}'

.PHONY: container
container:
	cp -RP ./* $(TEMP_DIR)
	$(DOCKER) build -t $(IMAGE):$(TAG) $(TEMP_DIR)/rootfs

.PHONY: push
push: .push
push:
	$(DOCKER) push $(IMAGE):$(TAG)
ifeq ($(ARCH), amd64)
	$(DOCKER) push $(IMAGE):$(TAG)
endif

.PHONY: clean
clean:
	$(DOCKER) rmi -f $(IMAGE):$(TAG) || true

.PHONE: code-generator
code-generator:
		go-bindata -o internal/file/bindata.go -prefix="rootfs" -pkg=file -ignore=Dockerfile -ignore=".DS_Store" rootfs/...

.PHONY: build
build: clean
	CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build -a -installsuffix cgo \
		-ldflags "-s -w -X ${PKG}/version.RELEASE=${TAG} -X ${PKG}/version.COMMIT=${COMMIT} -X ${PKG}/version.REPO=${REPO_INFO}" \
		-o ${TEMP_DIR}/rootfs/nginx-ingress-controller ${PKG}/cmd/nginx

.PHONY: verify-all
verify-all:
	@./hack/verify-all.sh

.PHONY: test
test:
	@go test -v -race -tags "$(BUILDTAGS) cgo" $(shell go list ${PKG}/... | grep -v vendor | grep -v '/test/e2e')

.PHONY: e2e-image
e2e-image: sub-container
	TAG=$(TAG) IMAGE=$(IMAGE) docker tag $(IMAGE):$(TAG) $(IMAGE):test
	docker images

.PHONY: e2e-test
e2e-test:
	@go test -o e2e-tests -c ./test/e2e
	@KUBECONFIG=${HOME}/.kube/config ./e2e-tests -test.parallel 1

.PHONY: cover
cover:
	@rm -rf coverage.txt
	@for d in `go list ./... | grep -v vendor | grep -v '/test/e2e'`; do \
		t=$$(date +%s); \
		go test -coverprofile=cover.out -covermode=atomic $$d || exit 1; \
		echo "Coverage test $$d took $$(($$(date +%s)-t)) seconds"; \
		if [ -f cover.out ]; then \
			cat cover.out >> coverage.txt; \
			rm cover.out; \
		fi; \
	done
	@echo "Uploading coverage results..."
	@curl -s https://codecov.io/bash | bash

.PHONY: vet
vet:
	@go vet $(shell go list ${PKG}/... | grep -v vendor)

.PHONY: luacheck
luacheck:
	luacheck -q ./rootfs/etc/nginx/lua/
