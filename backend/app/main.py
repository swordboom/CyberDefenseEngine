from .config import Settings
from .gateway import create_gateway_app


def create_app(config: Settings | None = None):
    return create_gateway_app(config)


app = create_app()
