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