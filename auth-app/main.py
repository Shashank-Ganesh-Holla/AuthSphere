from fastapi import FastAPI, Depends, HTTPException, status, Form, Request
from fastapi.security import OAuth2PasswordRequestForm
from auth import hash_password, verify_password, create_access_token, get_current_user, delete_user, validate_token, logout_user, role_required
from schemas import User, UserCreate, ClientResponse
from database import create_connection, execute_write_query, execute_read_query
from typing import Union
from fastapi.responses import JSONResponse
from fastapi import Request
from mysql.connector import Error
import pyotp

app = FastAPI()


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):

    '''Its nice to have the exception returned as a proper JSON response so this handles 
       any HTTPException response gracefully with format 
       
       {"stat" : "Not_Ok", "Reason": "..."}'''
    
    return JSONResponse(
        status_code=exc.status_code,
        content={"stat": "Not_Ok", "Reason": exc.detail},
    )



@app.get('/')
def read_root():
    return {"message":"Welcome to the Authentication App"}

# The response_model parameter is used in FastAPI to specify the format of the data that the endpoint should return to the client.
@app.post('/register', response_model=User)
def register(user:UserCreate,twoFA_enabled: bool = False):
    try:
        # create a connection to database
        connection = create_connection()

        # lets check if the user already exsists within table
        query_1 = "SELECT * FROM users where username = %s"
        params_1 = (user.username,)

        result = execute_read_query(connection,query_1,params_1)

        if result:
            raise HTTPException(status_code=200, detail="Username already registered!")

        
        hashed_password = hash_password(user.password)

        query = "INSERT INTO users (username, email, password, role_id) VALUES (%s, %s, %s, %s)"
        params = (user.username, user.email, hashed_password, user.role_id)

        if twoFA_enabled:
            try:
                # create a cursor
                cursor = connection.cursor()
                # start a transaction batch
                connection.start_transaction()

                # query params for pushing into users
                query_Users = "INSERT INTO users (username, email, password, role_id, enabled) VALUES (%s, %s, %s, %s, %s)"
                params_Users = (user.username, user.email, hashed_password, user.role_id, True)

                cursor.execute(query_Users, params_Users)

                # get a secretotp for the user(which is used later to generate unique otp everytime later)
                add_otpSecret = pyotp.random_base32()

                # query params for pushing into otp_table
                query_Otp = "INSERT INTO otp_table (username, otp_secret) VALUES (%s, %s)"
                params_Otp = (user.username, add_otpSecret)
                cursor.execute(query_Otp, params_Otp)

                connection.commit()

            except Error as e:
                print(f"Database error occured: {str(err)}")
                connection.rollback()
                print("Transaction rolled back")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,detail='Error while writing into database')

        execute_write_query(connection, query, params)

        # thanks to response_model defined in the decorator, though we return the user instance, the response_model validates the user and returns
        # only the attributes in User model, that is username and email not the password which is not ideal
        return user
    
    except Exception as err:
        print(f"An error occured {str(err)}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')


    finally:
        if connection:
            cursor.close()
            connection.close()



@app.post("/login")
def login(form_data:OAuth2PasswordRequestForm = Depends()):
    # first, the validation of input payload happens by the dependency class and assigns it to 'form_data' parameter
    
    # get the user from the 'from_data' param
    user = form_data.username
    plain_pwd = form_data.password

    try:

        # check if the user is in the table
        connection = create_connection()

        query_1 = "SELECT * FROM users WHERE username = %s"
        param_1 = (user,)

        user_db = execute_read_query(connection, query_1, param_1)
        if user_db:
            resp_pwd = user_db.get('password')
            resp_role = user_db.get('role_id')

            if resp_pwd and verify_password(plain_pwd, resp_pwd):

                if user_db.get('enabled') == 1 or user_db.get('enabled') == True:
                    query_2 = "SELECT * FROM otp_table WHERE username = %s"

                    otp_details = execute_read_query(connection,query_2, param_1)

                    if otp_details.get('otp_secret'):
                        return {"Result": "Enter OTP"}
                    
                    # in case of 'otp_secret' data not found for user for any reason(when enabled = True) 
                    # then disable twofa so that user can login using password
                    # and later update the 'otp_secret' using update_twofa endpoint and set enable twofa again!
                    else:
                        false_query = "UPDATE users SET enabled = %s WHERE username = %s AND enabled = %s"
                        false_params = (False, user, True)
                        
                        execute_write_query(connection, false_query, false_params)
                        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"OTP data not found for user: {user}, Please try login again!")

                data ={"sub":user, 'role': resp_role}
                access_token = create_access_token(data=data)
                return {"access_token": access_token, "token_type":"bearer"}

            else:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid Password")
                
        else:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    finally:
        if connection:
            connection.close()

@app.post('/verify_otp/')
def verify_otp(username: str = Form(...), otp:str = Form(...)):
    try:
        connection = create_connection()
        otp_query = "SELECT * FROM otp_table WHERE username = %s"
        otp_params = (username,)

        otp_details = execute_read_query(connection, otp_query, otp_params)

        if pyotp.TOTP(otp_details.get('otp_secret')).verify(otp):
            user_query = "SELECT * FROM users WHERE username = %s"
            user = execute_read_query(connection, user_query, otp_params)
            
            data = {'sub': otp_details.get('username'), 'role': user.get('role_id')}
            access_token = create_access_token(data)
            return {"access_token": access_token, "token_type": "bearer"}

        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")

    finally:
        if connection:
            connection.close()


@app.put('/update-twofa')
async def update_twofa(user : str = Depends(validate_token), twoFA_enabled:bool =False):
    try:
        username = user[0]

        connection = create_connection()

        # when twoFA_enabled param is False
        if not twoFA_enabled:
            # here we just need to update the enabled column of users table as False
            false_query = "UPDATE users SET enabled = %s WHERE username = %s AND enabled = %s"
            false_params = (False, username, True)
            
            execute_write_query(connection, false_query, false_params)

            return {"stat": "Ok", "Result": f"twoFA disabled successfully for {username} "} 
    
        # when twoFA_enabled param is True
        else:
            # here we have to do two things:
            # 1. check if the otp_secret in otp_table for the username is not None, if None then create a otpsecret and update, if not None then as is
            otp_scrt_query = "UPDATE otp_table SET otp_secret = %s WHERE username = %s AND otp_secret IS NULL"
            add_otpSecret = pyotp.random_base32()
            otp_scrt_param = (add_otpSecret, username)

            execute_write_query(connection, otp_scrt_query, otp_scrt_param)

            # 2. update the enabled column, checking if its already True, if not then update
            true_query = "UPDATE users SET enabled = %s WHERE username = %s AND enabled = %s"
            true_params = (True, username, False)

            execute_write_query(connection, true_query, true_params)

            return {"stat": "Ok", "Result": f"twoFA enabled successfully for {username} "}

    finally:
        if connection:
            connection.close()


@app.put('/assign-role/', dependencies=[Depends(role_required('admin'))])
def assign_role(username:str = Form(...), role_name:str = Form(...)):

    # get a connection to database
    connection = create_connection()
    
    # first check if the user exists 
    
    # query params for querying for username in the database 
    query_1 = "SELECT * FROM users WHERE username = %s"
    params_1 = (username,)

    result = execute_read_query(connection,query_1, params_1)

    # if user not found
    if not result:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found")
    
    # Now check if the role_name in roles table and get the role_id
    query_2 = "SELECT role_id FROM roles WHERE role_name = %s"
    params_2 = (role_name,)

    role_id = execute_read_query(connection, query_2, params_2)

    if not role_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="role_name not found")
    
    role_id = role_id.get('role_id')
    
    # now update the role id to the users table role_id column

    query_3 = "UPDATE users SET role_id = %s WHERE username = %s"
    params_3 = (role_id, username)


    result = execute_write_query(connection, query_3, params_3)

    connection.close()

    if result == 1 :
        return {"stat": "Ok",
                "Result": f"'{role_name}' role_name for '{username}' updated successfully! "}
    else:
        raise HTTPException(status.HTTP_200_OK, detail=f"'{role_name}' role already assigned!")


@app.get('/get-user-details/')
def get_user_details(username:str, current_user:None = Depends(validate_token)):

    # get a connection to database
    connection = create_connection()
    
    user_query = "SELECT * FROM users WHERE username = %s"
    user_param = (username,)

    is_user = execute_read_query(connection,user_query, user_param)

    if not is_user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found")

    details_query = '''
    SELECT u.username, u.email, r.role_name 
    FROM users u
    INNER JOIN roles r
    ON u.role_id = r.role_id
    WHERE u.username = %s
    '''

    details_params = (username,)

    result = execute_read_query(connection, details_query, details_params)

    if not result:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found or role not assigned")
    
    return {'stat': 'Ok',
            'Result': result}



@app.get('/users/me', response_model=Union[User])
def read_users_me(user:User=Depends(get_current_user)):
    return user


@app.post('/delete/user', response_model=Union[ClientResponse])
async def delete_user_me(request: Request, username:str = Form(...),
                   current_user:None = Depends(validate_token), 
                   ):
    
    user = await delete_user(username, request)

    return user

@app.post('/logout/', response_model=Union[ClientResponse])
async def logout_me(request:Request, 
                      username:str = Form(...),
                      current_user: None = Depends(validate_token)):
    user = await logout_user(username, request)
    return user




@app.get('/test-db')
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
        raise HTTPException(500, detail=repr(e))


if __name__ == "__main__":
    import uvicorn

    # For Debugging purpose only(Running application using IDE debugger)

    uvicorn.run(app)

