FROM golang:alpine AS builder

ARG CGO_ENABLED=0 
ARG GOOS=linux
ARG CMD_PATH
RUN go install github.com/google/wire/cmd/wire@latest

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY cmd cmd
COPY internal internal

RUN wire $CMD_PATH
RUN go build -o app $CMD_PATH

FROM alpine
LABEL maintainer="Sergey Kozhin <kozhinsergeyv@gmail.com>"
LABEL org.opencontainers.image.source=https://github.com/SergeyKozhin/blogin-auth

WORKDIR /app

COPY --from=builder /build/app .
EXPOSE 80
CMD ["./app"]
