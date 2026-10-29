# Build context MUST be the repository root: test the current worktree.
FROM golang:1.26.10@sha256:75bb407eabe887b4fe370e1c6176d4a26cc728338a12cc361f400715ed9577ad AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY tests/integration/go.mod tests/integration/go.sum ./tests/integration/
WORKDIR /src/tests/integration
RUN go mod download
WORKDIR /src
COPY *.go ./
COPY gen ./gen
COPY securechannel ./securechannel
COPY transport ./transport
COPY tests/integration/cmd ./tests/integration/cmd
COPY tests/integration/internal ./tests/integration/internal
WORKDIR /src/tests/integration
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -o /peer ./cmd/peer

# Build the released proxy from its checksum-verified module. GHCR currently
# denies anonymous pulls of the upstream image; this keeps local/CI identical.
FROM build AS toxiproxy-build
WORKDIR /go/pkg/mod/github.com/!shopify/toxiproxy/v2@v2.12.0
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags '-X github.com/Shopify/toxiproxy/v2.Version=2.12.0' -o /toxiproxy-server ./cmd/server

FROM scratch AS toxiproxy
COPY --from=toxiproxy-build /toxiproxy-server /toxiproxy-server
EXPOSE 8474 8666
ENTRYPOINT ["/toxiproxy-server"]

FROM scratch AS peer
COPY --from=build /peer /peer
EXPOSE 8080
ENTRYPOINT ["/peer"]
