from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import uvicorn

app = FastAPI()

# 🔹 Secret Key & Algorithm for JWT
SECRET_KEY = "thequickbrownfoxjumpedoverthelazydog"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# 🔹 Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
print(pwd_context.hash("helloworld"))

# 🔹 OAuth2 Scheme for JWT authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 🔹 Fake User Database (with hashed password)
fake_users_db = {
    "john": {
        "username": "john",
        "full_name": "John Doe",
        "email": "john@example.com",
        "hashed_password": pwd_context.hash("helloworld"),  # Store hashed password
        "disabled": False,
    }
}

# ✅ Function to verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# ✅ Function to get user from DB
def get_user(username: str):
    if username in fake_users_db:
        return fake_users_db[username]
    return None

# ✅ Function to create JWT token
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta  # Fix: Use utcnow()+ expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# 🔹 Login API (User Authentication)
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)  # 1️⃣ Check if user exists

    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    # 2️⃣ Generate JWT token
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {"access_token": access_token, "token_type": "bearer"}

# ✅ Function to verify JWT Token
def get_current_user(token: str = Depends(oauth2_scheme)):  #in token you will get encoded token 
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # when its decoded
        # payload={
        #     "sub": "john",
        #     "exp": 1710609850  # Expiry timestamp
        #     }
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return get_user(username)
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired or invalid")

# 🔹 Protected API (Only logged-in users can access)
@app.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    return {"message": f"Hello {current_user['username']}, you have access!"}



@app.get("/")
def hash():
    return print(pwd_context.hash("helloworld"))

if __name__=="__main__":
    uvicorn.run(app,host="localhost",port=8080)