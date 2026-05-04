from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import SQLAlchemyError
import logging
from app.config import settings
from app.routers import cve, stats, vulnerability, unified_search, osv, github_advisory, cwe, components, subscription
from app.database import engine, Base

logger = logging.getLogger(__name__)

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    redirect_slashes=False,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(cve.router, prefix=settings.API_V1_PREFIX, tags=["CVE"])
app.include_router(vulnerability.router, prefix=settings.API_V1_PREFIX + "/vulnerability", tags=["Vulnerability"])
app.include_router(unified_search.router, prefix=settings.API_V1_PREFIX + "/search", tags=["Unified Search"])
app.include_router(osv.router, prefix=settings.API_V1_PREFIX + "/osv", tags=["OSV"])
app.include_router(github_advisory.router, prefix=settings.API_V1_PREFIX + "/github-advisory", tags=["GitHub Advisory"])
app.include_router(stats.router, prefix=settings.API_V1_PREFIX, tags=["Stats"])
app.include_router(cwe.router, prefix=settings.API_V1_PREFIX + "/cwe", tags=["CWE"])
app.include_router(components.router, prefix=settings.API_V1_PREFIX, tags=["Components"])
app.include_router(subscription.router, prefix=settings.API_V1_PREFIX, tags=["Subscription"])


@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_exception_handler(request, exc):
    logger.error(f"Database error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Database error occurred", "error": str(exc)}
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=422,
        content={"detail": "Validation error", "error": str(exc)}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)}
    )


@app.get("/")
def read_root():
    return {"message": "网络安全漏洞情报平台 API", "version": "1.0.0"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}