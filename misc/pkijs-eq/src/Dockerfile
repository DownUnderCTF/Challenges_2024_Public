FROM node:22-alpine

RUN mkdir -p /home/node/app/node_modules && chown -R node:node /home/node/app

WORKDIR /home/node/app

COPY . .

RUN npm install

USER node

EXPOSE 1337

ENV FLAG DUCTF{deduplicate_and_decimate_07bca839bad0b201b9d}

CMD [ "node", "index.js" ]
