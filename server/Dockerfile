FROM node:20-alpine AS builder
WORKDIR /app

COPY package*.json ./
RUN npm install --no-audit --no-fund

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:20-alpine AS runtime
WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY --from=builder /app/dist ./dist

ARG SERVICE_ENTRY=core-api
ENV SERVICE_ENTRY=${SERVICE_ENTRY}
ENV NODE_ENV=production

CMD ["sh", "-c", "node dist/${SERVICE_ENTRY}.js"]
