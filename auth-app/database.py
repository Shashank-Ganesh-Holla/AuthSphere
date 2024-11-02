import mysql.connector 
from mysql.connector import Error
from fastapi import HTTPException
import os
from dotenv import load_dotenv


def create_connection():
    load_dotenv()
    connection = None

    try:
        connection = mysql.connector.connect(
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            host=os.getenv('DB_HOST'),
            database=os.getenv('DB_NAME'),
            collation=os.getenv('DB_COLLATION')  # Specify a compatible collation
        )
        
        return connection
    
    except Error as e:
        print(f'The error {repr(e)} occured')
        raise ConnectionError(f"Failed to connect to the database: {e}")  # Raise custom exception 

    except Exception as error:
        print(f'The error {repr(error)} occured')
        raise HTTPException(500, detail="Error in server")



def execute_write_query(connection, query, params=None):
    affected_rows = None
    try:
        
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        affected_rows = cursor.rowcount  # Number of rows affected by the query
        connection.commit()
        
    except Error as e:
        print(f"Error {e} occured!")
        raise HTTPException(500, detail="Error in server")
    
    finally:
        cursor.close()
    
    return affected_rows

def execute_read_query(connection, query, params=None):
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        result = cursor.fetchone()
        return result

    except Error as e:
        print(f"Error {e} occured!")
        raise ConnectionError(f"Database operation failure: {e}")
    
    finally:
        cursor.close()

            

def fetch_all_users(connection):
    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT * FROM  users")
        return cursor.fetchall()
    finally:
        if connection:
            if cursor: cursor.close()
            connection.close()

