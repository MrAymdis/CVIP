"""
定时增量同步任务
每天凌晨2点执行增量同步
直接使用数据库操作，不通过API接口
"""
import time
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.direct_db_sync import (
    sync_yesterday_direct,
    sync_incremental_by_date_direct
)


def schedule_daily_sync(hour: int = 2, minute: int = 0):
    """
    每天定时执行增量同步
    默认每天凌晨2点执行，直接同步前一天的数据
    """
    print(f"[{datetime.now()}] Scheduler started. Next sync at {hour:02d}:{minute:02d}")

    while True:
        now = datetime.now()
        next_sync_hour = hour

        if now.hour > hour or (now.hour == hour and now.minute >= minute):
            next_sync_hour = (hour + 24) % 24

        seconds_until_sync = (
            (24 - now.hour + next_sync_hour) * 3600
            - now.minute * 60
            - now.second
        )

        print(f"[{datetime.now()}] Next sync in {seconds_until_sync} seconds")
        time.sleep(seconds_until_sync)

        try:
            # 直接同步前一天的数据，不通过API接口
            yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            print(f"[{datetime.now()}] Direct sync for yesterday: {yesterday}")
            result = sync_yesterday_direct()
            print(f"[{datetime.now()}] Sync completed - Added: {result['added']}, Updated: {result['updated']}, Processed: {result['processed']}")
        except Exception as e:
            print(f"[{datetime.now()}] Scheduled sync error: {e}")

        time.sleep(60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="定时增量同步任务")
    parser.add_argument("--once", action="store_true", help="仅执行一次增量同步")
    parser.add_argument("--hour", type=int, default=2, help="定时同步的小时 (默认: 2)")
    parser.add_argument("--minute", type=int, default=0, help="定时同步的分钟 (默认: 0)")
    parser.add_argument("--date", type=str, help="指定日期同步（格式：YYYY-MM-DD）")

    args = parser.parse_args()

    if args.once:
        if args.date:
            result = sync_incremental_by_date_direct(args.date)
        else:
            result = sync_yesterday_direct()
        print(f"\n同步结果:")
        print(f"  新增组件: {result['added']}")
        print(f"  更新组件: {result['updated']}")
        print(f"  处理漏洞: {result['processed']}")
    else:
        schedule_daily_sync(hour=args.hour, minute=args.minute)
