from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routes.auth import router as auth_router
from app.routes.proxy import router as proxy_router
from app.routes.workspace import router as workspace_router

app = FastAPI(
    title="GateKeep API",
    description="Multi-Tenant LLM Security Gateway & Prompt Injection Firewall",
    version="1.0.0",
)

# Enable CORS for frontend dashboard (Next.js)
if settings.ENV == "production":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[origin.strip() for origin in settings.CORS_ORIGINS.split(",") if origin.strip()],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Register routers
app.include_router(auth_router)
app.include_router(workspace_router)
app.include_router(proxy_router)


@app.get("/health", tags=["Health"])
async def health_check(check_db: bool = False):
    """Service health check endpoint with optional database connectivity verification."""
    db_status = "unverified"
    if check_db:
        try:
            from app.repositories import get_repository

            repo = get_repository()
            if hasattr(repo, "table") and repo.table is not None:
                repo.table.load()
                db_status = "connected"
            else:
                db_status = "in_memory"
        except Exception as e:
            db_status = f"unhealthy: {str(e)}"

    return {
        "status": "healthy" if not db_status.startswith("unhealthy") else "degraded",
        "service": settings.APP_NAME,
        "env": settings.ENV,
        "database": db_status,
    }


@app.get("/", tags=["Health"])
async def root():
    return {
        "message": "Welcome to GateKeep — Multi-Tenant LLM Security Gateway & Prompt Injection Firewall",
        "docs": "/docs",
    }
