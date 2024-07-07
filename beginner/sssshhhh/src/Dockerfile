FROM golang:1.22 as build

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

COPY ./cmd ./cmd

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /server ./cmd 

# Needs to be base not static as ssh server requires ./ssh folder to be created
FROM gcr.io/distroless/base-debian12 as serve

COPY --from=build /server /server

EXPOSE 1337

ENV WARDEN="DUCTF{L00K_WhO53_L4uGh1nG-N0w-H4HaH4Hah4hA}"

ENTRYPOINT [ "/server" ]
