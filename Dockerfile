FROM golang:1.27.1 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o /broker ./cmd/broker \
    && CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags="-s -w" -o /portal ./cmd/portal \
    && mkdir /data

FROM scratch AS broker
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /broker /broker
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
ENV LISTEN_ADDR=:8080 DATA_DIR=/data
EXPOSE 8080
ENTRYPOINT ["/broker"]

FROM scratch AS portal
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /portal /portal
USER 65532:65532
ENV PORTAL_LISTEN_ADDR=:8788
EXPOSE 8788
ENTRYPOINT ["/portal"]

FROM broker AS final
