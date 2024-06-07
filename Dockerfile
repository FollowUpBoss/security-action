# Dockerfile used as GitHub action
FROM ghcr.io/aquasecurity/trivy:0.52.0
COPY entrypoint.sh /
COPY trivy_parser.py /
RUN apk --no-cache add bash curl npm python3 py3-pygithub
RUN chmod +x /entrypoint.sh
RUN chmod +x /trivy_parser.py
ENTRYPOINT ["/entrypoint.sh"]
