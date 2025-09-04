# ---- build stage ----
FROM node:20-alpine AS build
WORKDIR /app

# 의존성 설치
COPY package*.json ./
# lockfile이 있다면 npm ci 사용을 권장합니다:
# RUN npm ci
RUN npm install

# 앱 소스 복사 및 빌드
COPY . .
# CRA에서 CI 경고를 error로 취급하지 않게 하려면 다음 줄을 켤 수 있습니다:
# ENV CI=false
RUN npm run build

# ---- runtime stage ----
FROM nginx:1.27-alpine

# CRA 산출물(default: build)을 Nginx 루트로 복사
COPY --from=build /app/build /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

