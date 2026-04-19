from fastapi import APIRouter

from app.api.routes import adversarial, admin, audit, demo, health, metrics, shield

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(shield.router, prefix="/shield", tags=["shield"])
api_router.include_router(adversarial.router, prefix="/adversarial", tags=["adversarial"])
api_router.include_router(metrics.router, prefix="/metrics", tags=["metrics"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])
api_router.include_router(demo.router, prefix="/demo", tags=["demo"])
