# stopbard release image (CS-196). Built by goreleaser (dockers_v2) from the
# release binaries; `docker build` alone does not work, it expects them under
# $TARGETPLATFORM/. Distroless static: no shell, no package manager, uid 65532.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/stopbard /stopbard
USER nonroot:nonroot
EXPOSE 7777
# No default args: stopbard keeps its loopback default (127.0.0.1:7777), so the
# bare image is unreachable from outside the container. Serving on 0.0.0.0
# needs authentication, -auth-keys or mTLS (CS-103, ADR 0006); stopbard refuses a non-loopback listen without it.
ENTRYPOINT ["/stopbard"]
