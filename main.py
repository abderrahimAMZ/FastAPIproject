import zipfile
from typing import Annotated, Any

from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse
import shutil
import os

from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# models

class UserInfo(BaseModel):
    name : str
    email : str
    message : str

# what to add to origins so that all requests from localhost are allowed on all ports?
# https://stackoverflow.com/questions/63354853/how-to-allow-all-origins-in-fastapi



origins = [
    "http://localhost:5173",
    "http://localhost:49684",
    "http://localhost:43314",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# i have a client that is sending me a file in a POST request, and i want to store the file in my server.
# i want to use the File() type, but i also want to know the file size.

# let's write the endpoint to receive the file.




"""

@app.post("/files/")
async def create_file(file: Annotated[bytes, File()]):
    return {"file_size": len(file)}

"""

@app.post("/uploadfile/")
async def create_upload_file(file: UploadFile):
    return {"filename": file.filename}


@app.get("/")
async def root(idk):
    return {"message": f"{idk}"}

# how to set headers in fastapi
# https://fastapi.tiangolo.com/tutorial/cors/

@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}


"""
@app.post("/files")
async def save_user_info(user_info: UserInfo, file: UploadFile):
    temp_dir = "~/temp"
    os.mkdir(temp_dir, exists_ok=True)

    try:
        user_info_path = os.path.join(temp_dir, "user_info.json")
        with open(user_info_path, "w") as f:
            f.write(user_info.json())

        with zipfile.ZipFile(file.file, "r") as zip_ref:
            zip_ref.extractall(temp_dir)

        return {"message": "User info and file saved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        shutil.rmtree(temp_dir)

"""

@app.post("/user")
async def save_user_info(user_info: UserInfo, file : UploadFile):
    return {"message": "User info saved successfully" f"{user_info}, {file.filename}"}


@app.post("/files/")
async def create_file(

        file : UploadFile,
         name: str = Form(...),
        email: str = Form(...),
        message: str = Form(...)):

    file_location = f"saved_files/{file.filename}"

    with open(file_location, "wb+") as file_object:
        file_object.write(file.file.read())

    return {"info": "file successfully saved, for user info, see below", "user_info": f"{name}, {email}, {message}"}