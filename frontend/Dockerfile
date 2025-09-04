FROM nginx:1.27-alpine

# 헬스체크 엔드포인트(optional)
RUN printf 'server { listen 80; root /usr/share/nginx/html; \
location /health { return 200 "ok\n"; add_header Content-Type text/plain; } }' \
> /etc/nginx/conf.d/default.conf

COPY index.html /usr/share/nginx/html/index.html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

