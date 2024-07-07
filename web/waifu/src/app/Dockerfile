FROM node:20.14-bookworm-slim

COPY . /app
WORKDIR /app
RUN npm install && npm run build
RUN useradd --no-create-home app-user
USER app-user
CMD [ "npm", "run", "start" ]
