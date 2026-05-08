"""
用户认证功能测试
测试用户注册、登录、令牌刷新等功能
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import Base, get_db
from app.models.user import User
from app.models.role import Role
from app.services.auth import get_password_hash, verify_password

TEST_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=engine)
    yield TestClient(app)
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="module")
def test_role():
    db = TestingSessionLocal()
    admin_role = Role(name="admin", description="管理员角色")
    user_role = Role(name="user", description="普通用户角色")
    db.add(admin_role)
    db.add(user_role)
    db.commit()
    yield {"admin": admin_role, "user": user_role}
    db.close()


class TestUserRegistration:
    """测试用户注册"""

    def test_register_new_user(self, client):
        """测试注册新用户"""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "username": "testuser",
                "email": "test@example.com",
                "password": "testpass123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["email"] == "test@example.com"
        assert "id" in data

    def test_register_duplicate_username(self, client):
        """测试重复用户名注册"""
        client.post(
            "/api/v1/auth/register",
            json={
                "username": "duplicate",
                "email": "duplicate1@example.com",
                "password": "testpass123"
            }
        )
        response = client.post(
            "/api/v1/auth/register",
            json={
                "username": "duplicate",
                "email": "duplicate2@example.com",
                "password": "testpass123"
            }
        )
        assert response.status_code == 400

    def test_register_invalid_email(self, client):
        """测试无效邮箱注册"""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "username": "testuser2",
                "email": "invalid-email",
                "password": "testpass123"
            }
        )
        assert response.status_code == 422


class TestUserLogin:
    """测试用户登录"""

    def test_login_success(self, client, test_role):
        """测试成功登录"""
        client.post(
            "/api/v1/auth/register",
            json={
                "username": "logintest",
                "email": "login@example.com",
                "password": "testpass123"
            }
        )
        response = client.post(
            "/api/v1/auth/login",
            data={
                "username": "logintest",
                "password": "testpass123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password(self, client, test_role):
        """测试错误密码登录"""
        client.post(
            "/api/v1/auth/register",
            json={
                "username": "wrongpass",
                "email": "wrongpass@example.com",
                "password": "correctpass"
            }
        )
        response = client.post(
            "/api/v1/auth/login",
            data={
                "username": "wrongpass",
                "password": "wrongpass"
            }
        )
        assert response.status_code == 401

    def test_login_nonexistent_user(self, client):
        """测试不存在的用户登录"""
        response = client.post(
            "/api/v1/auth/login",
            data={
                "username": "nonexistent",
                "password": "somepass"
            }
        )
        assert response.status_code == 401


class TestTokenRefresh:
    """测试令牌刷新"""

    def test_refresh_token(self, client, test_role):
        """测试刷新令牌"""
        client.post(
            "/api/v1/auth/register",
            json={
                "username": "refreshtest",
                "email": "refresh@example.com",
                "password": "testpass123"
            }
        )
        login_response = client.post(
            "/api/v1/auth/login",
            data={
                "username": "refreshtest",
                "password": "testpass123"
            }
        )
        refresh_token = login_response.json()["refresh_token"]

        response = client.post(
            "/api/v1/auth/refresh-token",
            data={
                "refresh_token": refresh_token
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data


class TestProtectedEndpoints:
    """测试受保护的端点"""

    def test_access_protected_without_token(self, client):
        """测试无令牌访问受保护端点"""
        response = client.get("/api/v1/cve")
        assert response.status_code == 401

    def test_access_protected_with_valid_token(self, client, test_role):
        """测试有效令牌访问受保护端点"""
        client.post(
            "/api/v1/auth/register",
            json={
                "username": "accesstest",
                "email": "access@example.com",
                "password": "testpass123"
            }
        )
        login_response = client.post(
            "/api/v1/auth/login",
            data={
                "username": "accesstest",
                "password": "testpass123"
            }
        )
        access_token = login_response.json()["access_token"]

        response = client.get(
            "/api/v1/cve",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        assert response.status_code == 200

    def test_access_protected_with_invalid_token(self, client):
        """测试无效令牌访问受保护端点"""
        response = client.get(
            "/api/v1/cve",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401


class TestPasswordHashing:
    """测试密码哈希"""

    def test_password_hashing(self):
        """测试密码哈希和验证"""
        password = "testpassword123"
        hashed = get_password_hash(password)

        assert hashed != password
        assert verify_password(password, hashed)
        assert not verify_password("wrongpassword", hashed)

    def test_different_passwords_different_hashes(self):
        """测试不同密码产生不同哈希"""
        password1 = "password1"
        password2 = "password2"

        hash1 = get_password_hash(password1)
        hash2 = get_password_hash(password2)

        assert hash1 != hash2
