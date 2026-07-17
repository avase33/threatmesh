FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /threatmesh-gateway .

FROM gcr.io/distroless/static-debian12
COPY --from=build /threatmesh-gateway /threatmesh-gateway
ENV THREATMESH_HTTP_ADDR=:8080
EXPOSE 8080 5515
EXPOSE 5514/udp
ENTRYPOINT ["/threatmesh-gateway"]
