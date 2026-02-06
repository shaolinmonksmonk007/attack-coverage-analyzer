import uvicorn
from src.utils.config import config
from src.api.app import create_app

if __name__ == "__main__":
    app = create_app()
    uvicorn.run(app, host=config.API_HOST, port=config.API_PORT)
