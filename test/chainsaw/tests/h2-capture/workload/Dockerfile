# Non-stripped build so the Go crypto/tls uprobe resolves symbols without the
# gopclntab path (we're validating decode here, not stripped-binary support).
FROM golang:1.27.3-trixie@sha256:1896654cfc5c2b5ad74c07f29cb36f5d2d1cbed42e3054070fbfe444e521e83c AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /h2demo .

FROM gcr.io/distroless/static-debian12@sha256:a9fcaedd4c9b59e12dd65d954f0b5044f19b0647a8a3712e77205df9e7b102cd
COPY --from=build /h2demo /h2demo
ENTRYPOINT ["/h2demo"]
