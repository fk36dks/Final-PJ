FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
ENV PORT=5000
EXPOSE 5000
CMD ["node","server.js"]   # ← npm start 대신 server.js를 직접 실행

