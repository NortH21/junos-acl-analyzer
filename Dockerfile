FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

ARG TARGETOS TARGETARCH

# Шаблоны и статика встраиваются в бинарник (go:embed)
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags="-w -s" \
    -trimpath \
    -o /app/junos-acl-analyzer \
    .

FROM alpine:3.23

# tzdata нужен, чтобы TZ действительно применялся
RUN apk add --no-cache tzdata

ENV TZ=Europe/Moscow

RUN addgroup -g 1000 app && \
    adduser -D -u 1000 -G app appuser

WORKDIR /app

COPY --from=builder --chown=appuser:app /app/junos-acl-analyzer ./

USER appuser

EXPOSE 8080

CMD ["./junos-acl-analyzer"]
