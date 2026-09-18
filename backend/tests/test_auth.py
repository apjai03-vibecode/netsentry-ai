"""Unit and integration tests for Authentication and RBAC."""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    """Verify healthcheck endpoints return healthy status."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"

    response_api = await client.get("/api/health")
    assert response_api.status_code == 200


@pytest.mark.asyncio
async def test_register_user_success(client: AsyncClient):
    """Test successful user registration."""
    payload = {
        "username": "analyst1",
        "email": "analyst1@netsentry.internal",
        "password": "SecurePassword123!",
        "role": "analyst"
    }
    response = await client.post("/api/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "analyst1"
    assert data["email"] == "analyst1@netsentry.internal"
    assert data["role"] == "analyst"
    assert "id" in data
    assert "password" not in data
    assert "hashed_password" not in data


@pytest.mark.asyncio
async def test_register_duplicate_username_fails(client: AsyncClient):
    """Test registration fails when username already exists."""
    payload = {
        "username": "dup_user",
        "email": "user1@netsentry.internal",
        "password": "Password123!",
        "role": "analyst"
    }
    res1 = await client.post("/api/auth/register", json=payload)
    assert res1.status_code == 201

    payload_dup = {
        "username": "dup_user",
        "email": "user2@netsentry.internal",
        "password": "Password123!",
        "role": "analyst"
    }
    res2 = await client.post("/api/auth/register", json=payload_dup)
    assert res2.status_code == 400
    assert "Username already registered" in res2.json()["detail"]


@pytest.mark.asyncio
async def test_register_duplicate_email_fails(client: AsyncClient):
    """Test registration fails when email address already exists."""
    payload = {
        "username": "user_a",
        "email": "shared@netsentry.internal",
        "password": "Password123!",
        "role": "analyst"
    }
    res1 = await client.post("/api/auth/register", json=payload)
    assert res1.status_code == 201

    payload_dup = {
        "username": "user_b",
        "email": "shared@netsentry.internal",
        "password": "Password123!",
        "role": "analyst"
    }
    res2 = await client.post("/api/auth/register", json=payload_dup)
    assert res2.status_code == 400
    assert "Email address already registered" in res2.json()["detail"]


@pytest.mark.asyncio
async def test_login_json_success(client: AsyncClient):
    """Test login with JSON payload returns valid JWT."""
    # Register first
    await client.post("/api/auth/register", json={
        "username": "login_user",
        "email": "login_user@netsentry.internal",
        "password": "ValidPassword123!",
        "role": "analyst"
    })

    # Login
    response = await client.post("/api/auth/login/json", json={
        "username": "login_user",
        "password": "ValidPassword123!"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "login_user"


@pytest.mark.asyncio
async def test_login_form_success(client: AsyncClient):
    """Test OAuth2 form login returns valid JWT."""
    # Register first
    await client.post("/api/auth/register", json={
        "username": "form_user",
        "email": "form_user@netsentry.internal",
        "password": "ValidPassword123!",
        "role": "analyst"
    })

    # Login using form-data
    response = await client.post(
        "/api/auth/login",
        data={"username": "form_user", "password": "ValidPassword123!"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_invalid_password_fails(client: AsyncClient):
    """Test login with wrong password returns 401."""
    await client.post("/api/auth/register", json={
        "username": "wrong_pwd_user",
        "email": "wrong_pwd@netsentry.internal",
        "password": "CorrectPassword123!",
        "role": "analyst"
    })

    response = await client.post("/api/auth/login/json", json={
        "username": "wrong_pwd_user",
        "password": "WrongPassword456!"
    })
    assert response.status_code == 401
    assert "Incorrect username or password" in response.json()["detail"]


@pytest.mark.asyncio
async def test_get_current_user_me(client: AsyncClient):
    """Test fetching own profile with Bearer token."""
    await client.post("/api/auth/register", json={
        "username": "profile_user",
        "email": "profile@netsentry.internal",
        "password": "Password123!",
        "role": "analyst"
    })

    login_res = await client.post("/api/auth/login/json", json={
        "username": "profile_user",
        "password": "Password123!"
    })
    token = login_res.json()["access_token"]

    # Request /me with token
    headers = {"Authorization": f"Bearer {token}"}
    me_res = await client.get("/api/auth/me", headers=headers)
    assert me_res.status_code == 200
    data = me_res.json()
    assert data["username"] == "profile_user"
    assert data["email"] == "profile@netsentry.internal"


@pytest.mark.asyncio
async def test_unauthorized_access_fails(client: AsyncClient):
    """Test accessing protected route without auth token returns 401."""
    response = await client.get("/api/auth/me")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_role_based_access_control(client: AsyncClient):
    """Verify admin-only endpoint enforces role permissions."""
    # 1. Register analyst
    await client.post("/api/auth/register", json={
        "username": "analyst_rbac",
        "email": "analyst_rbac@netsentry.internal",
        "password": "Password123!",
        "role": "analyst"
    })
    login_analyst = await client.post("/api/auth/login/json", json={
        "username": "analyst_rbac",
        "password": "Password123!"
    })
    analyst_token = login_analyst.json()["access_token"]

    # 2. Register admin
    await client.post("/api/auth/register", json={
        "username": "admin_rbac",
        "email": "admin_rbac@netsentry.internal",
        "password": "Password123!",
        "role": "admin"
    })
    login_admin = await client.post("/api/auth/login/json", json={
        "username": "admin_rbac",
        "password": "Password123!"
    })
    admin_token = login_admin.json()["access_token"]

    # 3. Analyst accessing /api/auth/users -> 403 Forbidden
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
    res_forbidden = await client.get("/api/auth/users", headers=analyst_headers)
    assert res_forbidden.status_code == 403
    assert "Operation not permitted" in res_forbidden.json()["detail"]

    # 4. Admin accessing /api/auth/users -> 200 OK
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    res_admin = await client.get("/api/auth/users", headers=admin_headers)
    assert res_admin.status_code == 200
    users_list = res_admin.json()
    assert len(users_list) >= 2
