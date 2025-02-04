FROM node:21-alpine3.19
WORKDIR /usr/src/app
COPY package.* ./
RUN npm install
COPY . .