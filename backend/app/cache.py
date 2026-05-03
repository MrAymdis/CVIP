"""Redis 缓存工具模块"""
import redis
import json
from typing import Optional, Any, Callable
from functools import wraps
from app.config import settings

# 初始化 Redis 连接
redis_client = None

def get_redis_client():
    """获取 Redis 客户端"""
    global redis_client
    if redis_client is None:
        try:
            redis_client = redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_keepalive=True
            )
            # 测试连接
            redis_client.ping()
        except Exception as e:
            print(f"Redis 连接失败: {e}")
            redis_client = None
    return redis_client

def cache_result(ttl: int = 3600, key_prefix: str = "cache"):
    """
    缓存装饰器
    
    Args:
        ttl: 缓存过期时间（秒），默认3600秒(1小时)
        key_prefix: 缓存键前缀
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # 生成缓存键
            key_parts = [key_prefix, func.__name__]
            for arg in args:
                if hasattr(arg, '__dict__') and not isinstance(arg, (int, str, float, bool)):
                    continue
                key_parts.append(str(arg))
            for k, v in sorted(kwargs.items()):
                if k == 'db':
                    continue
                key_parts.append(f"{k}:{v}")
            cache_key = ":".join(key_parts)
            
            # 尝试从缓存获取
            client = get_redis_client()
            if client:
                try:
                    cached = client.get(cache_key)
                    if cached:
                        return json.loads(cached)
                except Exception as e:
                    print(f"Redis 读取失败: {e}")
            
            # 执行原函数
            result = await func(*args, **kwargs) if hasattr(func, '__code__') and 'async' in func.__code__.co_flags else func(*args, **kwargs)
            
            # 写入缓存
            if client:
                try:
                    # 处理 Pydantic 模型
                    serializable_data = result
                    if hasattr(result, "model_dump"):
                        serializable_data = result.model_dump()
                    elif hasattr(result, "dict"):
                        serializable_data = result.dict()
                    
                    client.setex(cache_key, ttl, json.dumps(serializable_data, default=str))
                except Exception as e:
                    print(f"Redis 写入失败: {e}")
            
            return result
        return wrapper
    return decorator

def cache_sync_result(ttl: int = 3600, key_prefix: str = "cache"):
    """
    同步函数的缓存装饰器
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 生成缓存键
            key_parts = [key_prefix, func.__name__]
            for arg in args:
                if hasattr(arg, '__dict__') and not isinstance(arg, (int, str, float, bool)):
                    continue
                key_parts.append(str(arg))
            for k, v in sorted(kwargs.items()):
                if k == 'db':
                    continue
                key_parts.append(f"{k}:{v}")
            cache_key = ":".join(key_parts)
            
            # 尝试从缓存获取
            client = get_redis_client()
            if client:
                try:
                    cached = client.get(cache_key)
                    if cached:
                        return json.loads(cached)
                except Exception as e:
                    print(f"Redis 读取失败: {e}")
            
            # 执行原函数
            result = func(*args, **kwargs)
            
            # 写入缓存
            if client:
                try:
                    # 处理 Pydantic 模型
                    serializable_data = result
                    if hasattr(result, "model_dump"):
                        serializable_data = result.model_dump()
                    elif hasattr(result, "dict"):
                        serializable_data = result.dict()
                    
                    client.setex(cache_key, ttl, json.dumps(serializable_data, default=str))
                except Exception as e:
                    print(f"Redis 写入失败: {e}")
            
            return result
        return wrapper
    return decorator

def invalidate_cache(pattern: str):
    """
    清除匹配的缓存
    
    Args:
        pattern: 键匹配模式
    """
    client = get_redis_client()
    if client:
        try:
            keys = client.keys(pattern)
            if keys:
                client.delete(*keys)
                print(f"已清除 {len(keys)} 个缓存键")
        except Exception as e:
            print(f"Redis 清除缓存失败: {e}")


def invalidate_stats_cache():
    """清除所有统计相关缓存"""
    invalidate_cache("stats:*")


def invalidate_search_cache():
    """清除所有搜索相关缓存"""
    invalidate_cache("search:*")


def invalidate_all_cache():
    """清除所有缓存"""
    invalidate_cache("*")


def clear_cache_after_update():
    """数据更新后清除相关缓存"""
    print("数据更新，清除相关缓存...")
    invalidate_stats_cache()
    invalidate_search_cache()
