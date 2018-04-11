# Copyright 2015 The Kubernetes Authors. All rights reserved.
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

FROM openresty/openresty:1.13.6.1-1-alpine

RUN apk add --no-cache diffutils dumb-init perl curl \
  && opm install knyar/nginx-lua-prometheus

# Create symlinks to redirect openresty logs to stdout and stderr docker log collector
# This only works if openresty is started with CMD or ENTRYPOINT
RUN mkdir -p /var/log/openresty \
  && ln -sf /dev/stdout /var/log/openresty/access.log \
  && ln -sf /dev/stderr /var/log/openresty/error.log

COPY . /

ENTRYPOINT ["/usr/bin/dumb-init"]

CMD ["/nginx-ingress-controller"]
