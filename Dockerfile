FROM node:20-alpine

WORKDIR /app

# Install dependencies first (better caching)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy app
COPY . .

ENV NODE_ENV=production \
    PORT=3003

EXPOSE 3003

CMD ["node", "server.js"]
