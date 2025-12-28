FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -trimpath \
    -o /app/junos-acl-analyzer \
    ./main.go

FROM alpine:3.18

ENV TZ=Europe/Moscow

RUN addgroup -g 1000 app && \
    adduser -D -u 1000 -G app appuser

WORKDIR /app

COPY --from=builder --chown=appuser:app /app/junos-acl-analyzer ./
COPY --from=builder --chown=appuser:app /app/templates ./templates/

USER appuser

EXPOSE 8080

CMD ["./junos-acl-analyzer"]

