# Nginx 1.29.1 고정
FROM nginx:1.29.1-alpine

# 기본 문서 루트 정리
RUN rm -rf /usr/share/nginx/html/*

# Nginx 설정 반영
COPY nginx/default.conf /etc/nginx/conf.d/default.conf

# 정적 파일 복사 (mypage.html을 메인으로, 새로 추가하는 페이지/이미지도 함께 복사)
# 필요에 맞게 경로 확장 가능
COPY ./*.html /usr/share/nginx/html/

EXPOSE 80

# 간단 헬스체크 (선택)
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD wget -qO- http://127.0.0.1/ || exit 1

