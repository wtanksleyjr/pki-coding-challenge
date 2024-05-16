# Start by building the executable.
FROM golang:1.22 as builder

# Set the working directory outside $GOPATH to enable the support for modules.
WORKDIR /app

# Copy the go.mod and go.sum file to download the dependencies.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code.
COPY . .

# Build the application.
RUN CGO_ENABLED=0 GOOS=linux go build -o lambda .

# Unit tests stage
FROM builder as tester
RUN go test ./...

# Final stage based on a lightweight base image.
FROM alpine:latest  
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the pre-built binary file from the previous stage.
COPY --from=builder /app/lambda .

# Run the server.
CMD ["./lambda"]
