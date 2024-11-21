from fastapi import APIRouter, HTTPException
from auth_app.database import create_connection
from aiomysql import Connection

router = APIRouter()


@router.get('/test-db')
async def test_db():
    try:
        connection : Connection = await create_connection()

        if connection:
            
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT 'Connection successfull!' AS message; ")
                result = cursor.fetchone()

            connection.close()
            return result


    except Exception as e:
        raise HTTPException(500, detail=str(e))