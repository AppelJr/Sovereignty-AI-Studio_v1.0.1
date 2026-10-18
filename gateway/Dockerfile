FROM python:3.13

WORKDIR /app

RUN pip install --no-cache-dir aiohttp httpx

COPY agents/ ./agents/
COPY event_bus/ ./event_bus/
COPY platform_connectors/ ./platform_connectors/
COPY plugin_sdk/ ./plugin_sdk/
COPY gateway/ ./gateway/

ENV PLUGIN_SDK_DIR=/app/plugin_sdk
ENV GATEWAY_PORT=9897

EXPOSE 9897

CMD ["python", "-m", "gateway.main"]
