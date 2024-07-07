FROM node:22-alpine

RUN mkdir -p /home/node/app/node_modules && chown -R node:node /home/node/app

WORKDIR /home/node/app

COPY . .

RUN npm install

USER node

EXPOSE 1337

ENV FLAG DUCTF{nice_splice_sice_a69bdb8eb2ca9e1}

CMD [ "node", "index.js" ]
