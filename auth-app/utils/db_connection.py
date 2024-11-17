from typing import AsyncGenerator
from fastapi import HTTPException, status
from database import create_connection, execute_read_query, execute_write_query
import logging
import aiomysql


# ! Context manager pattern !
class DatabaseManager:
    """Context manager to handle database connections.
    
    Establishes and closes database connections automatically
    and provides methods to execute read and write queries.
    """

    def __init__(self):

        '''init Optional in this scenario, still used it as a better practice'''

        self.connection = None

    async def __aenter__(self):
        """Creates a database connection when entering the context."""
        try:
            self.connection = await create_connection()
            return self
        except Exception as e:
            if not isinstance(e, HTTPException):
                logging.error(f"Failed to establish a database connection: {e}")

        return False # return False is enough to raise the exception if any, dont use raise here
    

    async def __aexit__(self, error_type, error_value, error_traceback):
        """Closes the database connection when exiting the context."""
        try:
            if self.connection: 
                self.connection.close()
        except Exception as e:
            if not isinstance(e, HTTPException):
                logging.error(f"Failed to close database connection: {e}")

        return False # return False is enough to raise the exception if any, dont use raise here


    async def execute_read(self, query, params):
        """Executes a read query on the database.""" 
        try:       
            result = await execute_read_query(self.connection, query, params)
            return result
        
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
            raise 

    
    
    async def execute_manipulation(self, query, params):
        """Executes a write (manipulation) query on the database."""
        try:
            result =  await execute_write_query(self.connection,query, params)
            return result
        except Exception as er:
            if not isinstance(er, HTTPException):
                logging.error(f"Error occured: {str(er)}")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
            raise 


async def get_db_connection()-> AsyncGenerator[DatabaseManager, None]:

    '''This method gets the control during the start of any route api and after the completion of the api request to close
    the connection'''

    try:

        async with DatabaseManager() as db:
            yield db

    except Exception as e:

        if not isinstance(e, HTTPException):
            logging.error(f"Error in database connection context: {e}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
        
        raise


# @asynccontextmanager
async def get_db_connection_batch_process()-> AsyncGenerator[aiomysql.Connection, None]:
   
    try:
        db  = await create_connection()
        await db.begin()  # Begin the transaction
        yield db        # Yield the connection to be used in the function

    except Exception as ex:
        await db.rollback() # Rollback in case of an error
        logging.warning("Transaction rolled back")

        if not isinstance(ex, HTTPException):  # incase of error other than HTTPException
            logging.error(f"Error occured : {str(ex)}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,detail="Internal Server Error")
        raise ex 
    
    finally:
        if db:
            db.close() # Close the connection when done