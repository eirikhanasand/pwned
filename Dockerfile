# Uses latest node alpine image for apk package manager
FROM node:alpine

# Sets the working directory
WORKDIR /usr/src/app

# Copies package.json and package-lock.json to the Docker environment
COPY package.json package-lock.json ./

# Installs required dependencies
RUN npm install

# Copies contents
COPY . .

# Stars the application
CMD npm start
