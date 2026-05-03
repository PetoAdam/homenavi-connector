FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/homenavi-connector ./src/backend/cmd/integration

FROM alpine:3.20
RUN adduser -D -H -u 10001 appuser
WORKDIR /app
COPY --from=build /out/homenavi-connector /app/homenavi-connector
COPY web /app/web
COPY manifest /app/manifest
USER appuser
EXPOSE 8099
ENV PORT=8099
CMD ["/app/homenavi-connector"]
