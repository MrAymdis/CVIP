"""
增量组件同步状态管理
管理同步时间戳，记录同步状态
"""
import redis
import os
from datetime import datetime
from typing import Optional

SYNC_TIMESTAMP_KEY = "component_sync:last_timestamp"

def get_redis_client():
    """获取Redis客户端"""
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    return redis.from_url(redis_url, decode_responses=True)


def get_last_sync_timestamp() -> Optional[str]:
    """
    获取上次同步时间戳
    返回 ISO 格式的时间字符串，如果不存在返回 None
    """
    try:
        client = get_redis_client()
        timestamp = client.get(SYNC_TIMESTAMP_KEY)
        client.close()
        return timestamp
    except Exception as e:
        print(f"Failed to get last sync timestamp: {e}")
        return None


def update_last_sync_timestamp(timestamp: Optional[str] = None) -> bool:
    """
    更新同步时间戳
    如果 timestamp 为 None，则使用当前时间
    """
    try:
        if timestamp is None:
            timestamp = datetime.utcnow().isoformat()

        client = get_redis_client()
        client.set(SYNC_TIMESTAMP_KEY, timestamp)
        client.close()
        return True
    except Exception as e:
        print(f"Failed to update last sync timestamp: {e}")
        return False


def get_last_sync_info() -> dict:
    """
    获取上次同步的信息
    """
    try:
        client = get_redis_client()
        timestamp = client.get(SYNC_TIMESTAMP_KEY)
        client.close()

        if timestamp:
            return {
                "last_sync_time": timestamp,
                "has_previous_sync": True
            }
        return {
            "last_sync_time": None,
            "has_previous_sync": False
        }
    except Exception as e:
        print(f"Failed to get last sync info: {e}")
        return {
            "last_sync_time": None,
            "has_previous_sync": False,
            "error": str(e)
        }


if __name__ == "__main__":
    print("Testing sync state management...")

    print(f"Last sync timestamp: {get_last_sync_timestamp()}")

    update_last_sync_timestamp()
    print(f"Updated timestamp: {get_last_sync_timestamp()}")

    print(f"Sync info: {get_last_sync_info()}")
