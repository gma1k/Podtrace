# Minimal OTLP/HTTP sink that logs printable strings from trace bodies, for e2e.
FROM golang:1.25@sha256:fe5d57d3b718e7a4986bae156c2d73f44973bfd313073aed08a4de6692bb6161 AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -o /otlp-sink .

FROM gcr.io/distroless/static-debian13@sha256:034df5c1737e8241f6ed6423a12e720ee0f6d6f088609ee172f98f6f2166ef5d
COPY --from=build /otlp-sink /otlp-sink
ENTRYPOINT ["/otlp-sink"]
