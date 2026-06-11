FROM golang:1.25 AS builder
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o modelsrv-web-ui-server ./cmd/modelsrv-web-ui-server

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/modelsrv-web-ui-server .
USER 65532:65532

ENTRYPOINT ["/modelsrv-web-ui-server"]
