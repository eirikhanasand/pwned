# Uses latest node alpine image for apk package manager
FROM oven/bun:alpine

# Sets the working directory
WORKDIR /usr/src/app

# Installs packages
RUN apk add ripgrep bash

# Copies package.json and bun.lock to the Docker environment
COPY package.json bun.lock ./

# Installs required dependencies
RUN bun install --frozen-lockfile

# Copies contents
COPY . .

# Stars the application
CMD bun start
