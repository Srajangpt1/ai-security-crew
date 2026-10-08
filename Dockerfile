# Use a Python image with uv pre-installed
FROM ghcr.io/astral-sh/uv:python3.10-alpine AS uv

# Install the project into `/app`
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy from the cache instead of linking since it's a mounted volume
ENV UV_LINK_MODE=copy

# Copy the project source code first
ADD . /app

# Install the project and its dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev --extra atlassian

# Remove unnecessary files from the virtual environment before copying
RUN find /app/.venv -name '__pycache__' -type d -exec rm -rf {} + && \
    find /app/.venv -name '*.pyc' -delete && \
    find /app/.venv -name '*.pyo' -delete && \
    echo "Cleaned up .venv"

# Final stage
FROM python:3.10-alpine

# Create a non-root user 'app'
RUN adduser -D -h /home/app -s /bin/sh app
WORKDIR /app
USER app

# Copy the virtual environment and the source code
COPY --from=uv --chown=app:app /app/.venv /app/.venv
COPY --from=uv --chown=app:app /app/src /app/src

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

# For minimal OAuth setup without environment variables, use:
# docker run -e ATLASSIAN_OAUTH_ENABLE=true -p 8000:8000 your-image
# Then provide authentication via headers:
# Authorization: Bearer <your_oauth_token>
# X-Atlassian-Cloud-Id: <your_cloud_id>

ENTRYPOINT ["mcp-security-review"]
