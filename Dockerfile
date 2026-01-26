FROM golang:1.25.6 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -o dnsstat ./cmd/...

FROM alpine:latest
RUN apk update && apk add --no-cache bash ca-certificates

WORKDIR /app

COPY --from=builder /app/dnsstat .
CMD ["/app/dnsstat"]