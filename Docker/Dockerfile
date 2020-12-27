#
# Run this container as 'docker run --rm -p 8443:8443 -p 8222:8222 <image>'
#
FROM alpine/socat
MAINTAINER Dmitry Golub <gdg.work@gmail.com>

# ADD requirements.txt

ENV LISTEN_EXT 8443
ENV LISTEN_INT 8222

ENTRYPOINT /usr/bin/socat "tcp4-listen:${LISTEN_EXT},fork,reuseaddr" "tcp4-listen:${LISTEN_INT},reuseaddr"

# see: https://www.ctl.io/developers/blog/post/docker-networking-rules/
EXPOSE ${LISTEN_EXT}:${LISTEN_EXT}
EXPOSE ${LISTEN_INT}:${LISTEN_INT}
