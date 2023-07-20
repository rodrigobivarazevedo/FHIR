from fastapi import FastAPI, HTTPException, Depends, status, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Dict
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

app = FastAPI()

# Define the models for our data
class Patient(BaseModel):
    id: int
    name: str
    age: int
    gender: str

class Record(BaseModel):
    id: int
    patient_id: int
    diagnosis: str
    medications: List[str] = []
    notes: str = ""

class User(BaseModel):
    username: str
    hashed_password: str
    disabled: bool

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str = None

# Define our database
db = {
    "patients": {},
    "records": {},
    "users": {}
}

# Define security settings
SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Define password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Define the routes for our API
@app.post("/patients")
async def create_patient(patient: Patient, current_user: User = Depends(get_current_user)):
    if patient.id in db["patients"]:
        raise HTTPException(status_code=400, detail="Patient already exists")
    db["patients"][patient.id] = patient
    return {"patient": patient}

@app.get("/patients")
async def read_patients(current_user: User = Depends(get_current_user)):
    return {"patients": db["patients"]}

@app.post("/records")
async def create_record(record: Record, current_user: User = Depends(get_current_user)):
    if record.id in db["records"]:
        raise HTTPException(status_code=400, detail="Record already exists")
    if record.patient_id not in db["patients"]:
        raise HTTPException(status_code=400, detail="Patient not found")
    db["records"][record.id] = record
    return {"record": record}

@app.get("/records")
async def read_records(current_user: User = Depends(get_current_user)):
    return {"records": db["records"]}

@app.get("/records/{patient_id}")
async def read_patient_records(patient_id: int, current_user: User = Depends(get_current_user)):
    if patient_id not in db["patients"]:
        raise HTTPException(status_code=400, detail="Patient not found")
    patient_records = []
    for record in db["records"].values():
        if record.patient_id == patient_id:
            patient_records.append(record)
    return {"records": patient_records}

# Define the routes for authentication and authorization
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db["users"], form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

def authenticate_user(users: Dict[str, User], username: str, password: str):
    if username in users:
        user = users[username]
        if not user.disabled and verify_password(password, user.hashed_password):
            return user

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db["users"].get(token_data.username)
    if user is None:
        raise credentials_exception
    return user

@app.post("/logout")
async def logout(response: Response, current_user: User = Depends(get_current_user)):
    response.delete_cookie(key="Authorization")
    return {"message": "Logged out successfully"}

