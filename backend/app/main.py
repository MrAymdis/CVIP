from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.routers import cve, stats, vulnerability, unified_search
from app.database import engine, Base

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    redirect_slashes=False,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(cve.router, prefix=settings.API_V1_PREFIX, tags=["CVE"])
app.include_router(vulnerability.router, prefix=settings.API_V1_PREFIX + "/vulnerability", tags=["Vulnerability"])
app.include_router(unified_search.router, prefix=settings.API_V1_PREFIX + "/search", tags=["Unified Search"])
app.include_router(stats.router, prefix=settings.API_V1_PREFIX, tags=["Stats"])


@app.get("/")
def read_root():
    return {"message": "网络安全漏洞情报平台 API", "version": "1.0.0"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}
