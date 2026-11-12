# --- build stage: compile the SPA -----------------------------------------
FROM node:22-alpine AS build
WORKDIR /app

# install first so this layer is cached until the lockfile changes
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# --- runtime stage: static files behind nginx, as a non-root user ----------
# The "unprivileged" image runs as uid 101 (nginx) and listens on 8080.
FROM nginxinc/nginx-unprivileged:1.30-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY proxy-gateway.conf /etc/nginx/proxy-gateway.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080
