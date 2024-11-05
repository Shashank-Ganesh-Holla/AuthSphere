from fastapi import APIRouter, HTTPException
from database import create_connection

router = APIRouter()


@router.get('/test-db')
def test_db():
    try:
        connection = create_connection()
        if connection:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT 'Connection successfull!' AS message; ")
                result = cursor.fetchone()
            connection.close()
            return result


    except Exception as e:
        raise HTTPException(500, detail=str(e))