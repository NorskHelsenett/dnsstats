FROM golang:1.25.5 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -o dnsstat ./cmd/...

FROM alpine:latest
RUN apk add --no-cache bash

WORKDIR /app

COPY --from=builder /app/dnsstat .
CMD ["/app/dnsstat"]