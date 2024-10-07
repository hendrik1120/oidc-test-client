FROM golang:1.23 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$BUILDPLATFORM go build -o oidc-test-client .

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata bash

WORKDIR /app

COPY templates/ ./templates/

COPY --from=builder /app/oidc-test-client .

EXPOSE 8080

CMD ["./oidc-test-client"]
