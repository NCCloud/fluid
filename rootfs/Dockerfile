FROM quay.io/easywp/openresty-base:1.1

LABEL maintainer="Valeriano Manassero <https://github.com/valeriano-manassero>"

COPY . /

ENTRYPOINT ["/usr/bin/dumb-init"]

CMD ["/nginx-ingress-controller"]
