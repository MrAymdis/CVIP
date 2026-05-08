from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import SQLAlchemyError
import logging
import asyncio
from app.config import settings
from app.routers import cve, stats, vulnerability, unified_search, osv, github_advisory, cwe, components, subscription
from app.database import engine, Base, get_db
from app.cache import get_redis_client, invalidate_stats_cache, invalidate_search_cache

logger = logging.getLogger(__name__)

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    redirect_slashes=False,
)


def warmup_cache():
    """启动时预热缓存，避免首次请求超时"""
    try:
        logger.info("Starting cache warmup...")
        
        # 确保Redis连接正常
        redis_client = get_redis_client()
        if not redis_client:
            logger.warning("Redis not available, skipping cache warmup")
            return
        
        # 清除旧缓存
        invalidate_stats_cache()
        invalidate_search_cache()
        
        # 等待服务启动
        import time
        time.sleep(2)
        
        # 使用HTTP请求预热缓存
        import requests
        
        # 预热统计缓存
        logger.info("Warming up stats cache...")
        try:
            response = requests.get("http://localhost:8000/api/v1/stats/overview", timeout=30)
            if response.status_code == 200:
                logger.info("Stats overview cached")
            else:
                logger.error(f"Failed to cache stats overview: {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to cache stats overview: {e}")
        
        # 预热热门漏洞缓存
        logger.info("Warming up top viewed cache...")
        try:
            response = requests.get("http://localhost:8000/api/v1/search/top-viewed?limit=10", timeout=30)
            if response.status_code == 200:
                logger.info("Top viewed vulnerabilities cached")
            else:
                logger.error(f"Failed to cache top viewed: {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to cache top viewed: {e}")
        
        # 预热默认搜索结果缓存
        logger.info("Warming up search cache...")
        try:
            response = requests.get("http://localhost:8000/api/v1/search?page=1&page_size=10", timeout=30)
            if response.status_code == 200:
                logger.info("Default search results cached")
            else:
                logger.error(f"Failed to cache search results: {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to cache search results: {e}")
        
        logger.info("Cache warmup completed")
    except Exception as e:
        logger.error(f"Cache warmup failed: {e}")


@app.on_event("startup")
async def startup_event():
    """启动时执行的初始化任务"""
    # 在后台线程中执行缓存预热，不阻塞启动
    import threading
    thread = threading.Thread(target=warmup_cache, daemon=True)
    thread.start()

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