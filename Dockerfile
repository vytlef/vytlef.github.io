# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go main_test.go ./
COPY web ./web
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${DATE}" \
    -o /out/cryptopic .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cryptopic /cryptopic
ENV PORT=8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/cryptopic"]
