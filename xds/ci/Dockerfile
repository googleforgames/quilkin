FROM golang:1.16-alpine

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY pkg/ pkg/

RUN go build -o /server cmd/controller.go

FROM alpine:latest
WORKDIR /app
COPY --from=0 /server ./

ENTRYPOINT [ "./server" ]
