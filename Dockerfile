# syntax=docker/dockerfile:1

FROM golang:1.26.2-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/threat-service ./cmd/server

FROM alpine:3.21 AS runtime

RUN apk add --no-cache ca-certificates \
    && addgroup -S app \
    && adduser -S -G app -u 10001 app

WORKDIR /app
COPY --from=build /out/threat-service /app/threat-service

USER app
EXPOSE 8080

ENTRYPOINT ["/app/threat-service"]
