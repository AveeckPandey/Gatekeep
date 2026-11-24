from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.routes.auth import router as auth_router
from app.routes.workspace import router as workspace_router
from app.routes.proxy import router as proxy_router

app = FastAPI(
    title="GateKeep API",
    description="Multi-Tenant LLM Security Gateway & Prompt Injection Firewall",
    version="1.0.0",
)

# Enable CORS for frontend dashboard (Next.js)
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
async def health_check():
    """Service health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "env": settings.ENV,
    }


@app.get("/", tags=["Health"])
async def root():
    return {
        "message": "Welcome to GateKeep — Multi-Tenant LLM Security Gateway & Prompt Injection Firewall",
        "docs": "/docs",
    }
