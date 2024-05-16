import math
from datetime import datetime, timedelta, timezone

from typing import Annotated, List

from pymongo import MongoClient

from fastapi import FastAPI, UploadFile, Form, HTTPException, Depends, status

from bson.objectid import ObjectId

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from fastapi.middleware.cors import CORSMiddleware

from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr



from fastapi_jwt_auth import AuthJWT

from passlib.context import CryptContext
from jose import JWTError, jwt

from gridfs import GridFS

import traceback, os, json, sendgrid

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from datetime import datetime

import random
import string


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "1aef19e98d5b41916153eb8d9ad98cce8a54037646bfe5c5080bfdc81388946d"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRECH_TOKEN_EXPI = 60*24*30

api_key = "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"


class File(BaseModel):
    filename: str
    content_type: str
    length: int
    upload_date: datetime

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: Annotated[str, Form(...)]
    email: Annotated[str, Form(...)]
    verified: bool = False
    files : List[File] = []



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



def get_file_details(file_id):
    try:
        file = fs.get(ObjectId(file_id))
        return {
        "file_id": str(file_id),  # Convert the ObjectId to a string
        "filename": file.filename,
        "content_type": file.content_type,
        "length": file.length,
        "upload_date": file.upload_date
        }
    except:
        traceback.print_exc()
        return {"message": "File not found"}


def send_verification_email(email, username):
    token = create_access_token(data={"sub": username})
    message = Mail(
        from_email=('unk1911@edeliverables.com','eDeliverables Automation'),
        to_emails=email,
        subject='Verify your email',
        html_content=f'<a href="http://localhost:8000/verify/{token}">Click here to verify your email</a>')
    try:
        sg = SendGridAPIClient(api_key=api_key)
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    user = users_collection.find_one({"$or": [{"email": username}, {"username": username}]})
    if user:
        username = user["username"]
        email = user["email"]
        hashed_password = user["hashed_password"]
        verified = user["verified"]

        return UserInDB(username=username, email=email, hashed_password=hashed_password, verified=verified)
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
        print(username)
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_verified_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.verified == False:
        raise HTTPException(status_code=400, detail="Email not verified. Please verify your email to continue.")
    return current_user


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    print(user)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    return Token(access_token=access_token, token_type="bearer")



@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)]
):

    user = users_collection.find_one({"username": current_user.username})
    file_ids = user.get("files", [])
    files = [get_file_details(file_id) for file_id in file_ids]
    current_user.files = files
    return current_user

@app.get("/users/{username}/files",response_model=List[File])
async def read_user_files(username: str):
    user = users_collection.find_one({"$or": [{"email": username}, {"username": username}]})
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    file_ids = user.get("files", [])
    files = [get_file_details(file_id) for file_id in file_ids]
    return files






@app.post("/users/create/")
async def create_user(username : Annotated[str,Form()], email: Annotated[EmailStr,Form()], password: Annotated[str, Form()]):
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
    user_data["verified"] = False


    # Insert the user data into the 'users' collection
    result = users_collection.insert_one(user_data)
    send_verification_email(email, username)
    # Return a success message
    return {"message": "User created successfully"}


# Access the 'files' collection

@app.post("/fileUpload/")
async def upload_file(

        file: UploadFile,
        User: Annotated[User, Depends(get_current_verified_user)]):

        user = users_collection.find_one({"username": User.username})

        if user:
            print(file.content_type)
            contents = await file.read()
            if file.content_type != "application/x-zip-compressed":
                raise HTTPException(400, detail="Invalid document type, please upload a zip file.")

            existing_file = fs.find_one({"filename": file.filename, "user_id": user["_id"]})
            if existing_file:
                # if existing file is found, delete it.
                fs.delete(existing_file._id)
                users_collection.update_one({"_id": user["_id"]}, {"$pull": {"files": existing_file._id}})

            file_id = fs.put(contents, filename=file.filename, content_type=file.content_type, user_id=user["_id"])

            users_collection.update_one({"_id": user["_id"]}, {"$push": {"files": file_id}})

            return {"message": "File stored successfully"}
        else:
            raise HTTPException(status_code=404, detail="User not found")


@app.delete("/fileDelete/{file_id}")
async def delete_file(file_id: str, User: Annotated[User, Depends(get_current_verified_user)]):
    user = users_collection.find_one({"username": User.username})
    if user:
        # Check if the file exists
        existing_file = fs.find_one({"_id": ObjectId(file_id), "user_id": user["_id"]})
        if not existing_file:
            raise HTTPException(404, detail="File not found.")

        # Delete the file from GridFS
        fs.delete(ObjectId(file_id))

        # Remove the file id from the user's files list
        users_collection.update_one({"_id": user["_id"]}, {"$pull": {"files": ObjectId(file_id)}})

        return {"message": "File deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="User not found")


@app.get("/verify/{token}", response_class=HTMLResponse)
async def verify_email(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=400, detail="Invalid token")
        user = users_collection.find_one({"$or": [{"username": username}, {"email": username}]})
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        users_collection.update_one({"$or": [{"username": username}, {"email": username}]}, {"$set": {"verified": True}})
        return """
        <html>
            <body>
                <h1><span style="color:green;">&#10004;</span> Email verified successfully</h1>
                <p>You can close this tab.</p>
            </body>
        </html>
        """
    except JWTError:
        return """
        <html>
            <body>
                <h1 style="color:red;">Verification failed</h1>
                <p>The verification token is invalid.</p>
            </body>
        </html>
        """
@app.post("/users/resend/")
async def resend_verification(username: Annotated[str, Form()]):
    user = users_collection.find_one({"$or": [{"username": username}, {"email": username}]})
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    send_verification_email(user["email"], username)
    return {"message": "Verification email resent successfully"}



class PasswordReset(BaseModel):
    email: str


def generate_verification_code(length=6):
    return ''.join(random.choice(string.digits) for _ in range(length))

@app.post("/password-reset/request")
async def request_password_reset(email: Annotated[EmailStr, Form(...)]):
    user = get_user(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    verification_code = generate_verification_code()

    # Store the verification code in the database
    users_collection.update_one({"email": user.email}, {"$set": {"password_reset_code": verification_code}})

    message = Mail(
        from_email=('unk1911@edeliverables.com','eDeliverables Automation'),
        to_emails=email,
        subject='Password Reset Request',
        html_content=f'<p>Your password reset code is: {verification_code}</p>'
    )

    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e)

    return {"message": "Password reset email sent"}

class PasswordResetPayload(BaseModel):
    password: str
    code: str

@app.post("/password-reset")
async def reset_password(password: Annotated[str, Form(...)], code: Annotated[str,Form(...)]):
    user = users_collection.find_one({"password_reset_code": code})
    if user is None:
        raise HTTPException(status_code=404, detail="Invalid code")

    hashed_password = get_password_hash(password)
    users_collection.update_one({"email": user["email"]}, {"$set": {"hashed_password": hashed_password, "password_reset_code": None}})

    return {"message": "Password reset successfully"}

