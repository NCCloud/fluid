FROM openresty/openresty:1.13.6.2-0-alpine

LABEL maintainer="Valeriano Manassero <https://github.com/valeriano-manassero>"

RUN apk add --no-cache \
    bash \
    dumb-init

COPY . /

ENTRYPOINT ["/usr/bin/dumb-init"]

CMD ["/nginx-ingress-controller"]
