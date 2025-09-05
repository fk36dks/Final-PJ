FROM node:20-alpine
WORKDIR /app

# install deps
COPY package*.json ./
RUN npm install --omit=dev

# copy source
COPY . .

# unify on port 5000
ENV PORT=5000
EXPOSE 5000

# always run server.js (헷갈리지 않게 npm start 대신 직접 실행)
CMD ["node", "server.js"]

