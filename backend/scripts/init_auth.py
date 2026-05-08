"""
初始化默认角色和管理员用户
运行此脚本创建默认角色（admin、user）和初始管理员账户
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal, engine, Base
from app.models.user import User
from app.models.role import Role
from app.services.auth import get_password_hash


def init_default_roles(db):
    """初始化默认角色"""
    roles_data = [
        {"name": "admin", "description": "管理员角色，拥有所有权限"},
        {"name": "user", "description": "普通用户角色，拥有基本访问权限"},
    ]

    for role_data in roles_data:
        existing_role = db.query(Role).filter(Role.name == role_data["name"]).first()
        if not existing_role:
            role = Role(**role_data)
            db.add(role)
            print(f"创建角色: {role_data['name']}")
        else:
            print(f"角色已存在: {role_data['name']}")

    db.commit()


def init_admin_user(db, username="admin", email="admin@example.com", password="admin123"):
    """初始化管理员用户"""
    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        print("错误: admin 角色不存在，请先运行 init_default_roles()")
        return None

    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        print(f"用户已存在: {username}")
        return existing_user

    admin_user = User(
        username=username,
        email=email,
        hashed_password=get_password_hash(password),
        is_active=True,
        role_id=admin_role.id
    )
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)
    print(f"创建管理员用户: {username}")
    return admin_user


def init_default_user(db, username="user", email="user@example.com", password="user123"):
    """初始化普通用户"""
    user_role = db.query(Role).filter(Role.name == "user").first()
    if not user_role:
        print("错误: user 角色不存在，请先运行 init_default_roles()")
        return None

    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        print(f"用户已存在: {username}")
        return existing_user

    user = User(
        username=username,
        email=email,
        hashed_password=get_password_hash(password),
        is_active=True,
        role_id=user_role.id
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    print(f"创建普通用户: {username}")
    return user


def main():
    """主函数"""
    print("开始初始化数据库...")
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        print("\n1. 初始化默认角色...")
        init_default_roles(db)

        print("\n2. 初始化管理员用户...")
        admin = init_admin_user(db)

        print("\n3. 初始化普通用户...")
        user = init_default_user(db)

        print("\n初始化完成！")
        print("\n默认账户信息:")
        print("-" * 50)
        print(f"管理员 - 用户名: admin, 密码: admin123, 角色: admin")
        print(f"普通用户 - 用户名: user, 密码: user123, 角色: user")
        print("-" * 50)
        print("\n请尽快修改默认密码！")

    except Exception as e:
        print(f"初始化失败: {e}")
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    main()
