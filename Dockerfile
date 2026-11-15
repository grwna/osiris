FROM golang:1.26-alpine AS build

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.Version=0.1.0" -o /osiris ./cmd/osiris

FROM alpine:3.20

COPY --from=build /osiris /osiris
ENTRYPOINT ["/osiris"]
