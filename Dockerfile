# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o /out/layer-audit .

# ---- runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/layer-audit /layer-audit
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/layer-audit"]
