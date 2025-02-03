from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

# FastAPI setup
app = FastAPI()

# Retrieve values from environment variables
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "auth_db")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "users")

# Set up MongoDB client and database
client = AsyncIOMotorClient(MONGO_URI)
db = client[DATABASE_NAME]
collection = db[COLLECTION_NAME]

# Set up password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# CORS setup (allowing all origins for simplicity)
origins = [
    "*",  # Wildcard to allow all origins (use with caution)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allow all origins or specify a list of trusted domains
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)

# Pydantic model for login and user creation request
class UserRequest(BaseModel):
    username: str
    password: str

# Utility function to verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Utility function to hash password
def hash_password(password):
    return pwd_context.hash(password)

# Create a user (for initial setup, not part of the login flow)
@app.post("/create_user")
async def create_user(request: UserRequest):
    # Hash the password
    hashed_password = hash_password(request.password)
    
    # Check if the user already exists
    existing_user = await collection.find_one({"username": request.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Insert user into MongoDB
    new_user = {
        "username": request.username,
        "password": hashed_password
    }
    result = await collection.insert_one(new_user)
    
    # Return response with user_id as a string
    return {"status": "success", "message": "User created", "user_id": str(result.inserted_id)}

@app.post("/login")
async def login(request: UserRequest):
    # Retrieve user from MongoDB
    user = await collection.find_one({"username": request.username})
    if user and verify_password(request.password, user["password"]):
        return {"status": "success", "message": "Authentication successful"}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/")
async def read_root():
    return {"message": "Hello, World!"}
