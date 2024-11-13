import boto3
import os
from botocore.exceptions import ClientError, NoCredentialsError
import logging


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
        logging.error(f"Error uploading file: {e}")
        return False

    except NoCredentialsError as e:
        logging.error("Credentials not available")
        return False
    
    except Exception as e:
        logging.error(f"Error occured : {str(e)}")
    

