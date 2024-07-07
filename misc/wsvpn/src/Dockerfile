FROM golang:1.22.2 as builder

WORKDIR /app

COPY go.mod go.sum /app/

COPY src /app/

ENV CGO_ENABLED=0

RUN go build -o wsvpn main.go

FROM scratch

COPY --from=builder /app/wsvpn /wsvpn

ENV FLAG=DUCTF{websockets_rule_Ahquo8Gahnetich0}

EXPOSE 1337

ENTRYPOINT [ "/wsvpn", "-addr", "0.0.0.0:1337" ]