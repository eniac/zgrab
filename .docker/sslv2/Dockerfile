FROM centos:5.11
RUN openssl genrsa -out server.key 1024; \
    openssl req -new -key server.key -out server.req -batch; \
    openssl req -x509 -in server.req -out server.pem -key server.key;
EXPOSE 443
CMD ["openssl", "s_server", \
        "-accept", "443", \
        "-key", "server.key", \
        "-cert", "server.pem", \
	"-ssl2" \
    ]
