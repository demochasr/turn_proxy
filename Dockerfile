FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o vk-turn-proxy ./server

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -S turnproxy && adduser -S -G turnproxy -h /app turnproxy

WORKDIR /app

COPY --chown=turnproxy:turnproxy docker-entrypoint.sh .
COPY --chown=turnproxy:turnproxy --from=builder /build/vk-turn-proxy .
RUN chmod +x docker-entrypoint.sh

EXPOSE 56000/udp

USER turnproxy

ENTRYPOINT ["./docker-entrypoint.sh"]
