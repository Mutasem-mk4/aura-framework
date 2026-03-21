from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

app = FastAPI()

# Database simulation
users = {
    1: {"name": "Admin", "is_admin": True},
    2: {"name": "User1", "is_admin": False}
}

class UserUpdate(BaseModel):
    name: str
    is_admin: bool = False

@app.get("/")
def read_root():
    return {"message": "Welcome to the Vulnerable Lab"}

@app.get("/api/v1/users/{user_id}")
def get_user(user_id: int):
    # Vulnerable to IDOR - no check on current user context
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    return users[user_id]

@app.post("/api/v1/users/{user_id}/update")
def update_user(user_id: int, update: UserUpdate):
    # Vulnerable to BOLA and Mass Assignment
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    users[user_id].update(update.dict())
    return {"status": "success", "user": users[user_id]}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5000)
