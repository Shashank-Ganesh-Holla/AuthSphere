import boto3
import os
from botocore.exceptions import ClientError, NoCredentialsError
import logging
from fastapi import HTTPException


s3_client = boto3.client('s3',
                         aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID"),
                         aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY"),
                         region_name = os.getenv("AWS_REGION"))



# s3_client = boto3.client('s3')
# print(dir(s3_client))




def upload_file_to_s3(filepath:str, bucket, object_name:str):

    if object_name is None:
        object_name = os.path.basename(filepath)

    try:
        s3_client.upload_file(filepath, bucket, object_name)
        return True

    except ClientError as e:
        logging.warning(f"Error uploading file: {e}")
        return False

    except NoCredentialsError as e:
        logging.warning("Credentials not available")
        return False
    
    except Exception as e:
        logging.error(f"Error occured : {str(e)}")



async def download_from_s3(filename:str, bucket):

    try:
        file_url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket, 'Key': filename},
            ExpiresIn = 3600
        )

        return file_url

    except ClientError as e:
        logging.warning(f"Error downloading file: {e}")
        raise HTTPException(500, f"Client error: {str(e)}")


    except Exception as e:
        logging.error(f"Error occured : {str(e)}")
        raise HTTPException(500, f"Error occured: {str(e)}")


    

