from fastapi import FastAPI
from src.api.routes import router

def create_app() -> FastAPI:
    app = FastAPI(
        title="ATT&CK Coverage Analyzer",
        description="Automated MITRE ATT&CK Mapping & Gap Analysis Tool",
        version="0.1.0",
    )
    app.include_router(router, prefix="/api")
    return app
