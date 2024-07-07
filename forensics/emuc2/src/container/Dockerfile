FROM clux/muslrust:stable as backend
COPY src/emuc2-backend /build/
WORKDIR /build/
RUN cargo build --release



FROM node:22-alpine as frontend
COPY src/emuc2-dashboard /build/
WORKDIR /build/
RUN yarn install
RUN yarn build



FROM python:3.11-alpine as artifacts
COPY src/emuc2-artifacts /build/
WORKDIR /build/
RUN pip install -r requirements.txt
RUN python3 build.py



FROM scratch
COPY --from=frontend /build/dist /static/
COPY --from=artifacts /build/landingzone/chall/ /
COPY --from=backend /build/target/x86_64-unknown-linux-musl/release/emuc2-backend /backend

ENV ROCKET_PORT 1337
CMD ["/backend"]
