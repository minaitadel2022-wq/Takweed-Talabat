FROM node:18-alpine

WORKDIR /app

# Install dependencies first (better layer caching on rebuilds)
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# Copy the rest of the app
COPY . .

# Where persistent data (data.json, users.json, activity.json, backups/) lives.
# Mount a persistent volume at this path on your cloud provider so data survives
# restarts/redeploys — see README "النشر على أي كلاود".
ENV DATA_DIR=/data
RUN mkdir -p /data

EXPOSE 3000
ENV PORT=3000

# Basic container healthcheck most orchestrators (Docker, k8s, ECS...) understand.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "require('http').get('http://localhost:'+(process.env.PORT||3000)+'/health', r => process.exit(r.statusCode===200?0:1)).on('error', () => process.exit(1))"

CMD ["node", "server.js"]
