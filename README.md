# iot-auth

Shared JWT authentication library for Django and FastAPI microservices. Provides middleware, decorators, and dependencies for consistent token validation and permission checks.

## Installation

```bash
pip install git+https://github.com/IoT-Hub-Alpha/jwt-auth-lib.git
```

## Configuration

The library reads configuration from environment variables (set via docker-compose from umbrella repo):

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET_KEY` | - | Secret key for JWT validation (required) |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `INTERNAL_SERVICE_HEADER` | `X-Internal-Service` | Header for service-to-service auth bypass |

## JWT Payload Structure

The library expects tokens with this payload:

```json
{
  "sub": "user-uuid",
  "username": "operator1",
  "email": "operator@example.com",
  "groups": ["operators"],
  "permissions": ["devices.view", "devices.add"],
  "is_staff": true,
  "is_superuser": false,
  "exp": 1234568790,
  "iat": 1234567890,
  "type": "access"
}
```

## Django Usage

### 1. Add Middleware

```python
# settings.py
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # ... other middleware
    "iot_auth.django.JWTAuthMiddleware",  # Add this
]
```

The middleware:
- Extracts JWT from `Authorization: Bearer <token>` header
- Validates and decodes the token
- Attaches payload to `request.auth`
- Returns `400 {"error": "invalid token"}` for bad/missing tokens
- Bypasses auth for internal service requests

### 2. Function-Based Views

```python
from django.http import JsonResponse
from iot_auth.django import check_permissions, require_auth
from iot_auth.types import JWTPayload

# Just requires authentication (no specific permission)
@require_auth
def profile(request) -> JsonResponse:
    auth: JWTPayload = request.auth
    return JsonResponse({"user": auth["username"]})

# Requires specific permission
@check_permissions("devices.view")
def list_devices(request) -> JsonResponse:
    return JsonResponse({"devices": []})

# Requires multiple permissions (user must have ALL)
@check_permissions("devices.view", "devices.edit")
def edit_device(request) -> JsonResponse:
    return JsonResponse({"success": True})
```

### 3. Class-Based Views

```python
from django.views import View
from django.http import JsonResponse
from iot_auth.django import CheckPermissionsMixin

# Same permissions for all methods
class DeviceListView(CheckPermissionsMixin, View):
    required_permissions = ["devices.view"]

    def get(self, request) -> JsonResponse:
        user_id = request.auth["sub"]
        return JsonResponse({"devices": []})
```

### 4. Per-Method Permissions (Class-Based Views)

Use `permission_map` to apply different permissions for each HTTP method:

```python
class DeviceView(CheckPermissionsMixin, View):
    permission_map = {
        "get": ["devices.view"],
        "post": ["devices.add"],
        "put": ["devices.edit"],
        "delete": ["devices.delete"],
    }

    def get(self, request) -> JsonResponse:
        return JsonResponse({"devices": []})

    def post(self, request) -> JsonResponse:
        return JsonResponse({"created": True})

    def put(self, request) -> JsonResponse:
        return JsonResponse({"updated": True})

    def delete(self, request) -> JsonResponse:
        return JsonResponse({"deleted": True})
```

**How it works:**
- `permission_map` takes precedence over `required_permissions`
- Methods not in `permission_map` fall back to `required_permissions`
- Superusers and internal requests bypass all checks

```python
# Mixed usage: permission_map + fallback
class DeviceView(CheckPermissionsMixin, View):
    required_permissions = ["devices.view"]  # Fallback for methods not in map
    permission_map = {
        "post": ["devices.add"],
        "delete": ["devices.delete"],
    }

    def get(self, request) -> JsonResponse:
        # Uses required_permissions (devices.view)
        return JsonResponse({"devices": []})

    def post(self, request) -> JsonResponse:
        # Uses permission_map (devices.add)
        return JsonResponse({"created": True})
```

## FastAPI Usage

### 1. Basic Authentication

```python
from fastapi import Depends, FastAPI
from iot_auth.fastapi import get_current_user
from iot_auth.types import JWTPayload

app = FastAPI()

@app.get("/devices")
async def list_devices(auth: JWTPayload = Depends(get_current_user)):
    user_id = auth["sub"]
    return {"devices": [], "user": auth["username"]}
```

### 2. Permission Checks

```python
from iot_auth.fastapi import require_permissions

@app.get("/devices")
async def list_devices(
    auth: JWTPayload = Depends(require_permissions("devices.view"))
):
    return {"devices": []}

# Multiple permissions (user must have ALL)
@app.post("/devices")
async def create_device(
    auth: JWTPayload = Depends(require_permissions("devices.view", "devices.add"))
):
    return {"created": True}
```

### 3. Optional Authentication

```python
from typing import Optional
from iot_auth.fastapi import get_optional_user

@app.get("/public")
async def public_endpoint(
    auth: Optional[JWTPayload] = Depends(get_optional_user)
):
    if auth:
        return {"message": f"Hello, {auth['username']}"}
    return {"message": "Hello, guest"}
```

## Service-to-Service Communication

Internal requests between services can bypass JWT authentication by including the `X-Internal-Service` header:

```python
import requests

# From notification-service calling device-service
response = requests.get(
    "http://device-service:8000/api/devices",
    headers={"X-Internal-Service": "notification-service"}
)
```

Both middleware and permission decorators allow internal requests through without token validation.

## Error Responses

| Scenario | Status | Response |
|----------|--------|----------|
| Missing/invalid/expired token | 400 | `{"error": "invalid token"}` |
| Missing permissions | 401 | `{"error": "Not authorized"}` |

## Superusers

Users with `is_superuser: true` in their JWT payload automatically pass all permission checks.

## Type Hints

The library provides `JWTPayload` TypedDict for IDE autocompletion:

```python
from iot_auth.types import JWTPayload

def my_view(request) -> JsonResponse:
    auth: JWTPayload = request.auth
    auth["sub"]          # IDE knows this is str
    auth["permissions"]  # IDE knows this is list[str]
```

## Testing

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v
```
