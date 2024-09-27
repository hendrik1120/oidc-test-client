FROM golang:1.23 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o oidc-test-client .

FROM alpine:latest  

WORKDIR /app

COPY --from=builder /app/oidc-test-client .

EXPOSE 8080

CMD ["./oidc-test-client"]
