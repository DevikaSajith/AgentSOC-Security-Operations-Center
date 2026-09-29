"""`python -m app` starts the API using BACKEND_HOST / BACKEND_PORT from the environment."""

import uvicorn

from app.config import get_settings

if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run("app.main:app", host=settings.host, port=settings.port)
