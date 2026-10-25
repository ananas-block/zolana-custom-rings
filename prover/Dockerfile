# The client prover serves Zolana's native circuits and the custom-ring extension.
# Both lockfiles are embedded in the combined binary. Keys are fetched and
# verified on demand, so this image carries no proving keys.
FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

WORKDIR /src
COPY zolana/prover/server/go.mod zolana/prover/server/go.sum /src/zolana/prover/server/
COPY prover/go.mod prover/go.sum /src/prover/
WORKDIR /src/prover
RUN go mod download && go mod verify

COPY zolana/prover/server/ /src/zolana/prover/server/
COPY prover/ /src/prover/

ARG GOAMD64
ARG PROVER_PGO
RUN GOAMD64="$GOAMD64" PROVER_PGO="$PROVER_PGO" \
    sh /src/zolana/prover/server/build-release.sh /usr/local/bin/light-prover ./cmd/prover
RUN mkdir -p /tmp/empty_proving_keys

FROM gcr.io/distroless/base-debian11:nonroot@sha256:68b0f492c1eb077f71d384b544456dac4afb282372966917df32b3923f65ad0d

COPY --from=builder /usr/local/bin/light-prover /usr/local/bin/light-prover
COPY --chown=nonroot:nonroot --from=builder /tmp/empty_proving_keys /proving-keys/

WORKDIR /
EXPOSE 3001 9998
ENTRYPOINT ["light-prover"]
CMD ["start", "--require-optimized-build"]
