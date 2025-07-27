import asyncio
import httpx
import os
from app.main import app
from app.config.settings import Settings
from app.core.jwt import jwt_service

async def debug_test():
    # Create admin token
    admin_token = jwt_service.create_access_token(
        subject="test-admin-id",
        scopes=["admin:users"],
        audience=["test-api"],
        roles=["admin"],
        username="admin",
        email="admin@example.com",
    )
    
    print(f"Admin token: {admin_token}")
    
    # Test the endpoint
    async with httpx.AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        print(f"Status: {response.status_code}")
        print(f"Headers: {response.headers}")
        print(f"Content: {response.text}")

if __name__ == "__main__":
    asyncio.run(debug_test())