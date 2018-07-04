FROM openresty/openresty:1.13.6.2-0-alpine

LABEL maintainer="Valeriano Manassero <https://github.com/valeriano-manassero>"

RUN apk update \
    && rm -rf /var/cache/apk/* \
    && apk add --update --no-cache \
       bash \
       dumb-init

COPY . /

ENTRYPOINT ["/usr/bin/dumb-init"]

CMD ["/nginx-ingress-controller"]
