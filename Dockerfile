# ---- Stage 1: The Builder ----
FROM node:20 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .

# ---- Stage 2: The Final Production Image ----
FROM node:20-slim
WORKDIR /app
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 amini
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app .
USER amini
EXPOSE 3000
CMD [ "node", "amini-docker-project/server.js" ]