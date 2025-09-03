FROM node:20-alpine

WORKDIR /app

# Install dependencies first (better caching)
COPY package*.json ./
# Use npm install to be tolerant of minor lockfile drift
RUN npm install --omit=dev --no-audit --no-fund

# Copy app
COPY . .

# Optionally set at build time: docker build --build-arg COMMIT=... --build-arg BUILD_TIME=...
ARG COMMIT
ARG BUILD_TIME
ENV BUILD_COMMIT=${COMMIT} \
    BUILD_TIME=${BUILD_TIME}

ENV NODE_ENV=production \
    PORT=3003

EXPOSE 3003

CMD ["node", "server.js"]
