
from typing import Annotated

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

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

@app.post("/files/")
async def create_file(file: bytes = File(...)):
    return {"file_size": len(file)}


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
