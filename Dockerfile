FROM python:3-alpine

ARG VERSION=dev

LABEL org.opencontainers.image.title="HeaderHornet" \
      org.opencontainers.image.description="Email header analyzer with browser UI and JSON API" \
      org.opencontainers.image.source="https://github.com/emmolab/headerhornet" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HEADERHORNET_DEBUG=0

WORKDIR /usr/src/mha

COPY requirements.txt ./
RUN apk add --no-cache gcc musl-dev && \
    pip install --no-cache-dir -r requirements.txt

COPY mha/ .

EXPOSE 8080

ENTRYPOINT ["python", "/usr/src/mha/server.py", "-b", "0.0.0.0"]
CMD ["-p", "8080"]
