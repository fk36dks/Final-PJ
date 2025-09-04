# Nginx 1.29.1 고정
FROM nginx:1.29.1-alpine

# 기본 문서 루트 비우기
RUN rm -rf /usr/share/nginx/html/*

# Nginx 설정
COPY nginx/default.conf /etc/nginx/conf.d/default.conf

# 정적 파일: public/ 전체를 문서루트로 복사
COPY public/ /usr/share/nginx/html/

# (선택) Jenkins 빌드번호를 버전 파일로 굽기
ARG BUILD_TAG
RUN [ -n "$BUILD_TAG" ] && echo "$BUILD_TAG" > /usr/share/nginx/html/version.txt || true

EXPOSE 80

# 헬스체크: /healthz
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget -qO- http://127.0.0.1/healthz || exit 1

