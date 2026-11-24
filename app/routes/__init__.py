from app.routes.auth import router as auth_router
from app.routes.workspace import router as workspace_router
from app.routes.proxy import router as proxy_router

__all__ = ["auth_router", "workspace_router", "proxy_router"]
