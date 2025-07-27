"""Test script to isolate dependency injection issue."""

from fastapi import FastAPI, Depends, HTTPException, status
from app.core.security import require_admin, get_current_user
from app.models.user import User

app = FastAPI()

# Test 1: Direct require_admin usage
@app.get("/test1")
async def test1(current_user: User = Depends(require_admin())):
    return {"message": "Test 1 success", "user": current_user.username}

# Test 2: Basic get_current_user
@app.get("/test2")
async def test2(current_user: User = Depends(get_current_user)):
    return {"message": "Test 2 success", "user": current_user.username}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)