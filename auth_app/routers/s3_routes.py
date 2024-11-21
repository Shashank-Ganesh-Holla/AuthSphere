from fastapi import File, UploadFile, APIRouter, HTTPException, Depends
from auth_app.utils import upload_file_to_s3, download_from_s3, validate_token
import logging
import tempfile
from auth_app.core import websocket_manager
from datetime import datetime
import os


router = APIRouter()

BUCKET_NAME = "authsphere-user-files"


@router.post("/upload-file/")
async def upload_file(file:UploadFile = File(...), current_user:None = Depends(validate_token)):

    try:
    
        '''First lets store the input file into the local temporary folder'''

        '''tempfile.NamedTemporaryFile creates a temporary file and is compatible with all OS'''

        with tempfile.NamedTemporaryFile(delete=False) as temp:

            file_path = temp.name

            with open(file_path, "wb") as buffer:
                buffer.write(await file.read())

            logging.info(f"File saved at {file_path}")
            

        '''Once the file is stored locally, we push it into AWS s3 bucket by giving the local filepath to s3 upload '''

        if upload_file_to_s3(filepath=file_path, bucket=BUCKET_NAME, object_name=file.filename):

            # remove temporary file from the server machine
            os.remove(file_path)
            
            logging.info(f"Temporary file {file_path} deleted")

            #Websocket broadcast message
            await websocket_manager.broadcast( f"File {file.filename} uploaded successfully into AWS s3 bucket")
            return {"stat": "Ok", "message": "File uploaded successfully", "filename": file.filename}
        
        #Websocket broadcast message
        await websocket_manager.broadcast( f"File {file.filename} upload failed!")
        return HTTPException(500, "File upload failed")
    
    except Exception as e:
        if not isinstance(e, HTTPException):
            logging.error(f"Error occured : {str(e)}")

            await websocket_manager.broadcast(f"{datetime.now()} :Result: {str(e)}")
            raise HTTPException(500, "Internal Server Error")
        
        await websocket_manager.broadcast(f"{datetime.now()} :Result: {e.detail}")
        raise


@router.get("/download-file/{file_name}")
async def download_file(file_name:str, current_user:None = Depends(validate_token)):

    # This generate a Pre-signed URL or directly stream the file from S3,
    # valid for a limited period of time which is specified when the URL is generated

    try:
        file_url = await download_from_s3(filename=file_name, bucket=BUCKET_NAME)

        await websocket_manager.broadcast( f"File {file_name} downloaded successfully")
        return {"url":file_url}
    
    except Exception as e:
        if not isinstance(e, HTTPException):
            logging.error(f"Error occured : {str(e)}")
            await websocket_manager.broadcast(f"{datetime.now()} :Result: {str(e)}")
            raise HTTPException(500, "Internal Server Error")
        
        await websocket_manager.broadcast(f"{datetime.now()} :Result: {e.detail}")
        raise