FROM node:20-buster-slim

WORKDIR /ctf
COPY main-app/ .

RUN npm install

EXPOSE 1337

CMD [ "node", "/ctf/server.js" ]
