FROM node:24.14.0-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --chown=node:node src ./src
COPY --chown=node:node examples ./examples
COPY --chown=node:node config.example.json LICENSE ./
USER node
CMD ["node", "src/cli.js", "demo"]
