from datetime import datetime, timedelta, timezone

from typing import Annotated, List

from pymongo import MongoClient

from fastapi import FastAPI, UploadFile, Form, HTTPException, Depends, status

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel, EmailStr

from passlib.context import CryptContext
from jose import JWTError, jwt

from gridfs import GridFS


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "1aef19e98d5b41916153eb8d9ad98cce8a54037646bfe5c5080bfdc81388946d"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30





class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None



class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


origins = ["*"]

# Set all CORS enabled origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# db connection
client = MongoClient('mongodb://localhost:27017/')
db = client['users']
users_collection = db['users']
fs = GridFS(db)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    user = users_collection.find_one({"email": username})
    if user:
        username = user["username"]
        email = user["email"]
        hashed_password = user["hashed_password"]

        return UserInDB(username=username, email=email, hashed_password=hashed_password)
    return None


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
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
    user = get_user(token_data.username)
    if user is None:
        raise credentials_exception
    return user




@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
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
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)]
):
    return current_user








@app.post("/users/create/")
async def create_user(username: Annotated[str, Form()], email : Annotated[EmailStr, Form()],password: Annotated[str, Form()]):
    # Convert the user data to a dictionary so it can be stored in MongoDB

    existing_user = users_collection.find_one({"username": username})

    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")


    hashed_password = get_password_hash(password)

    user_data = {}
    user_data["username"] = username
    user_data["email"] = email
    user_data["hashed_password"] = hashed_password
    user_data["files"] = []


    # Insert the user data into the 'users' collection
    result = users_collection.insert_one(user_data)

    # Return a success message
    return {"message": "User created successfully"}


# Access the 'files' collection

@app.post("/fileUpload/")
async def upload_file(

        file : UploadFile,
        User : Annotated[User, Depends(get_current_user)]):

        user = users_collection.find_one({"username": User.username})
        if user:
            contents = await file.read()

            file_id = fs.put(contents, filename=file.filename, content_type=file.content_type, user_id=user["_id"])

            users_collection.update_one({"_id": user["_id"]}, {"$push": {"files": file_id}})

            return {"message": "File stored successfully"}
        else:
            raise HTTPException(status_code=404, detail="User not found")

        return {"message": "File created successfully" f"{User.username} {User.email}"}


