FROM golang:1.25 AS builder
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o modelsrv-web-ui-server ./cmd/modelsrv-web-ui-server

FROM alpine:3.22 AS ui
ARG UI_VERSION=v0.4.4-rc
RUN wget -qO- "https://github.com/emeland-io/emeland-ui/releases/download/${UI_VERSION}/emeland-ui-${UI_VERSION}.tar.gz" \
    | tar -xz -C /tmp

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/modelsrv-web-ui-server .
COPY --from=ui /tmp /static
USER 65532:65532

ENTRYPOINT ["/modelsrv-web-ui-server", "--static-dir", "/static"]
