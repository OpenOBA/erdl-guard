# Build stage: compile TypeScript with devDependencies.
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY src ./src
COPY tsconfig.json ./
RUN npm run build

# Runtime stage: production deps only.
FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY erdl ./erdl
EXPOSE 3001
ENTRYPOINT ["node", "dist/cli.js", "serve"]
