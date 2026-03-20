FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -o /vaydns-server ./vaydns-server
RUN CGO_ENABLED=0 go build -o /vaydns-client ./vaydns-client

FROM alpine
RUN apk add --no-cache curl
COPY --from=build /vaydns-server /usr/local/bin/
COPY --from=build /vaydns-client /usr/local/bin/
