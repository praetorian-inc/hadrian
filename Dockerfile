FROM golang:1.25 AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /bin/hadrian ./cmd/hadrian

FROM gcr.io/distroless/static-debian12
COPY --from=build /bin/hadrian /usr/local/bin/hadrian
ENTRYPOINT ["hadrian"]
