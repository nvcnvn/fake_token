FROM golang:1.12.5 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends git

COPY . /app/
WORKDIR /app/
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o fake_token main.go

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /app/
ENV PORT=":8080"
ENV KEYS_GLOB="./private_pems/*.pem"
ENV TEMPLATES_GLOB="./templates/*.template"
ENV CERT_NOT_BEFORE="Jan 2 15:04:05 2006"
ENV CERT_NOT_AFTER="Jan 2 15:04:05 2026"
COPY --from=builder /app/ .
ENTRYPOINT [ "./fake_token" ]