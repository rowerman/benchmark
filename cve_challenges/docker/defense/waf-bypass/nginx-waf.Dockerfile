FROM nginx:alpine

# Copy custom nginx config with WAF rules
COPY nginx/default.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
