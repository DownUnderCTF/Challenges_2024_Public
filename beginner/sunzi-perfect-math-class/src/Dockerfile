FROM node:22.3.0-alpine3.19 as development

WORKDIR /app

COPY package.json /app/package.json
COPY package-lock.json /app/package-lock.json

RUN npm ci

COPY . /app

ENV CI=true
ENV PORT=3000

CMD [ "npm", "run", "dev"]

FROM development as build
RUN npm run build


FROM nginx:alpine

COPY --from=build /app/.nginx/nginx.conf /etc/nginx/conf.d/default.conf
WORKDIR /usr/share/nginx/html

RUN rm -rf ./*

COPY --from=build /app/dist .
ENTRYPOINT [ "nginx" , "-g", "daemon off;"]

