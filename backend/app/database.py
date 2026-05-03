from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://cve:cvepassword@localhost:5432/cve_db")

# 优化数据库连接池配置
engine = create_engine(
    DATABASE_URL,
    pool_size=20,              # 连接池大小
    max_overflow=30,           # 最大溢出连接数
    pool_timeout=30,           # 获取连接超时时间(秒)
    pool_recycle=3600,         # 连接回收时间(秒) - 1小时
    pool_pre_ping=True,        # 连接前自动ping检查
    echo=False                 # 不打印SQL语句
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
