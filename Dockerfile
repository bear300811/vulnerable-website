# Intentionally vulnerable test target. Do not expose to the public internet.
FROM node:24-alpine

WORKDIR /app

# Node built-ins only: no npm install step.
COPY server.js ./
COPY public ./public

# Writable folders used by the upload and file endpoints.
RUN mkdir -p files uploads && chown -R node:node files uploads

ENV HOST=0.0.0.0 \
    PORT=8000
EXPOSE 8000

USER node
CMD ["node", "server.js"]
