proxy_http_version 1.1;

# Do not buffer, cache, transform, or retry data-plane requests.
proxy_request_buffering off;
proxy_buffering off;
proxy_cache off;
gzip off;
proxy_next_upstream off;

proxy_connect_timeout 5s;
proxy_send_timeout 1h;
proxy_read_timeout 1h;

# Preserve ordinary request headers, but replace forwarding identity with
# values established by this trusted edge. Configure real_ip separately if a
# trusted load balancer is deployed in front of this Nginx instance.
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Port $server_port;
proxy_set_header Forwarded "";

# Passthrough NewAPI routes may still use WebSocket upgrades. Configured audit
# routes are POST-only and do not expand the proxy's WebSocket boundary.
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $connection_upgrade;
