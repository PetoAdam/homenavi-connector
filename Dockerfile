FROM golang:1.26.4-alpine3.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/homenavi-connector ./src/backend/cmd/integration

FROM alpine:3.21
RUN adduser -D -H -u 10001 appuser
WORKDIR /app
COPY --from=build /out/homenavi-connector /app/homenavi-connector
COPY web /app/web
COPY manifest /app/manifest
RUN mkdir -p /app/config && chown -R 10001:10001 /app
USER appuser
EXPOSE 8099
ENV PORT=8099
CMD ["/app/homenavi-connector"]
