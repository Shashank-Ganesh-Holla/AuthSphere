# import mysql.connector 
# from mysql.connector import Error
from fastapi import HTTPException
import os
from dotenv import load_dotenv
import logging
from aiomysql import connect, Error, Connection, DictCursor
from typing import Optional

load_dotenv()

async def create_connection() -> Connection:
    
    connection = None

    try:
        connection = await connect(
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            host=os.getenv('DB_HOST'),
            # for aiomysql, db is a keyword argument for database
            db=os.getenv('DB_NAME')
        )
        
        return connection
    
    except Error as err:
        logging.warning(str(err))
        raise ConnectionError(f"Failed to connect to the database: {str(err)}")  # Raise custom exception 

    except Exception as error:
        logging.error(str(error))
        raise HTTPException(500, detail="Error in server")



async def execute_write_query(connection:Connection, query, params=None):
    
    affected_rows = None

    try:
        async with connection.cursor(DictCursor) as cursor:
            await cursor.execute(query, params)
            affected_rows = cursor.rowcount  # Number of rows affected by the query
            await connection.commit()
            return affected_rows
        
    except Error as er:
        if not isinstance(er, HTTPException):
            logging.warning(f" Error occured: {str(er)}")
            raise  HTTPException(500, detail="Internal Server Error")
        else:
            raise
    
    except Exception as err:
    
        if not isinstance(err, HTTPException):
            logging.error(f" Error occured: {str(err)}")
            raise  HTTPException(500, detail="Internal Server Error")
        else:
            raise


async def execute_read_query(connection:Connection, query, 
                       params=None):
    
    try:
        async with connection.cursor(DictCursor) as cursor:
            await cursor.execute(query, params)
            result = await cursor.fetchone()
            return result

    except Exception as e:
        if not isinstance(e, HTTPException):
            logging.error(f" Error occured: {str(e)}")
            raise  HTTPException(500, detail="Internal Server Error")
        else:
            raise
    

            

async def fetch_all_users(connection:Connection):
    try:
        async with connection.cursor(DictCursor) as cursor:
            await cursor.execute("SELECT * FROM  users")
            result = await cursor.fetchall()
            return result
    
    finally:
        if connection:
            if cursor: cursor.close()
            connection.close()

