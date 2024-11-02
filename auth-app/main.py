from fastapi import FastAPI, Depends, HTTPException, status, Form, Request
from fastapi.security import OAuth2PasswordRequestForm
from schemas import User, UserCreate, ClientResponse
from database import create_connection
from typing import Union
from fastapi.responses import JSONResponse
from fastapi import Request
from mysql.connector import Error
import pyotp
from auth import TokenFactory, TokenManager, UserManager, RoleManager, PasswordManager, DatabaseManager

app = FastAPI()


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):

    """
    Custom exception handler for HTTP exceptions, returning a structured JSON response.
    
    This handler intercepts HTTPException responses and formats them in a standardized JSON structure, 
    enhancing readability and consistency across API responses. The output format is:
    
    {
        "stat": "Not_Ok",
        "Reason": "..."
    }
    
    This approach provides a user-friendly and professional error response for clients.
    """
    
    return JSONResponse(
        status_code=exc.status_code,
        content={"stat": "Not_Ok", "Reason": exc.detail},
    )



@app.get('/')
def read_root():
    return {"message":"Welcome to the Authentication App"}

# The response_model parameter is used in FastAPI to specify the format of the data that the endpoint should return to the client.
@app.post('/register', response_model=User)
def register(user:UserCreate):

    try:
        # lets check if the user already exsists within table
        query_user = "SELECT * FROM users where username = %s"
        params_user = (user.username,)

        with DatabaseManager() as db:
            result = db.execute_read(query_user, params_user)

        if result:
            raise HTTPException(status_code=200, detail="Username already registered!")

        hashed_password = PasswordManager.hash_password(user.password)

        if user.twoFA_enabled:

            try:
                connection = create_connection()
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
                query_Otp ='''INSERT INTO otp_table (username, otp_secret) VALUES (%s, %s)
                    ON DUPLICATE KEY
                    UPDATE otp_secret = IF(otp_secret IS NULL, VALUES(otp_secret), otp_Secret)
                    '''
                
                params_Otp = (user.username, add_otpSecret)
                cursor.execute(query_Otp, params_Otp)

                connection.commit()
                cursor.close()
                
            except Error as err:
                print(f"Database error occured: {str(err)}")
                connection.rollback()
                print("Transaction rolled back")
                raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,detail='Error while writing into database')
            
            
        query = "INSERT INTO users (username, email, password, role_id) VALUES (%s, %s, %s, %s)"
        params = (user.username, user.email, hashed_password, user.role_id)

        with DatabaseManager() as db:
            db.execute_manipulation(query, params)

        return user
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            print(f"An error occured {str(err)}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise

    finally:
        if connection:
            connection.close()
                

@app.post("/login")
def login(form_data:OAuth2PasswordRequestForm = Depends()):

    try:
        user = form_data.username
        plain_pwd = form_data.password

        param_user = (user,)
        with DatabaseManager() as db:
            query_user = "SELECT * FROM users WHERE username = %s"
            user_db = db.execute_read(query_user, param_user)

        if user_db:
            resp_pwd = user_db.get('password')
            resp_role = user_db.get('role_id')

            if resp_pwd and PasswordManager.verify_password(plain_pwd, resp_pwd):

                if user_db.get('enabled') == 1 or user_db.get('enabled') == True:

                    '''For user who have enabled twofa(password and otp)'''

                    with DatabaseManager() as db:
                        query_otp = "SELECT * FROM otp_table WHERE username = %s"
                        otp_details = db.execute_read(query_otp, param_user)

                    if otp_details.get('otp_secret'):
                        otp = pyotp.TOTP(otp_details.get('otp_secret'))
                        otp_gen = otp.now()
                        
                        # Send this otp generated by otp_gen to the user chosen medium of communication(otp sent as email or sms)
                        # but now, will include otp_gen within the reponse of login for testing purpose
                        # will change it later when communicating with users is added

                        return {'otp': otp_gen,"Result": "Enter OTP"}

                    else:

                        '''Reset the twofa as disabled and ask to relogin as the otp_secrt data for the user not found in database.
                        Can be set /update_twofa endpoint once the user login with password'''

                        with DatabaseManager() as db:
                            false_query = "UPDATE users SET enabled = %s WHERE username = %s AND enabled = %s"
                            false_params = (False, user, True)
                            db.execute_manipulation(false_query, false_params)
                        
                        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"OTP data not found for user: {user}, Please try login again!")

                '''For users with only password authentication'''

                data ={"sub":user, 'role': resp_role}

                access_token = TokenFactory.create_access_token(data=data)

                return {"access_token": access_token, "token_type":"bearer"}

            else:
                '''When wrong password entered'''
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid Password")
                
        else:
            '''When username entered not valid'''
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found")
        
    except Exception as err:
        if not isinstance(err, HTTPException):
            print(f"An error occured {str(err)}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise


@app.post('/verify_otp/')
def verify_otp(username: str = Form(...), otp:str = Form(...)):

    try:

        with DatabaseManager() as db:
            otp_query = "SELECT * FROM otp_table WHERE username = %s"
            otp_params = (username,)

            otp_details = db.execute_read(otp_query, otp_params)

        if pyotp.TOTP(otp_details.get('otp_secret')).verify(otp):

            user_query = "SELECT * FROM users WHERE username = %s"

            with DatabaseManager() as db:
                user = db.execute_read(user_query, otp_params)
            
            data = {'sub': otp_details.get('username'), 'role': user.get('role_id')}

            access_token = TokenFactory.create_access_token(data)

            return {"access_token": access_token, "token_type": "bearer"}

        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            print(f"An error occured {str(err)}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise


@app.put('/update-twofa')
async def update_twofa(user : str = Depends(TokenFactory.validate_token), twoFA_enabled:bool= Form(False)):
    try:
        username = user[0]   

        if not twoFA_enabled:
            '''when twoFA_enabled param is False'''

            # here we just need to update the enabled column of users table as False
            with DatabaseManager() as db:
                false_query = "UPDATE users SET enabled = %s WHERE username = %s AND enabled = %s"
                false_params = (False, username, True)
                
                set_false = db.execute_manipulation(false_query, false_params)
            
            if set_false == 1:
                return {"stat": "Ok", "Result": f"twoFA disabled successfully for {username} "}
            else:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Could not update resource, twoFA already disabled")
            
        else:
            '''when twoFA_enabled param is True'''
            # here we have to do two things:
            # 1. check if the otp_secret in otp_table for the username is not None, 
            # if None then create a otpsecret and update, if not None then as is
            with DatabaseManager() as db:

                otp_scrt_query = "UPDATE otp_table SET otp_secret = %s WHERE username = %s AND otp_secret IS NULL"
                add_otpSecret = pyotp.random_base32()
                otp_scrt_param = (add_otpSecret, username)
                db.execute_manipulation(otp_scrt_query, otp_scrt_param)

            # 2. update the enabled column, checking if its already True, if not then update
            with DatabaseManager() as db:
                true_query = "UPDATE users SET enabled = %s WHERE username = %s AND enabled = %s"
                true_params = (True, username, False)
                set_true = db.execute_manipulation(true_query, true_params)

            if set_true == 1:
                return {"stat": "Ok", "Result": f"twoFA enabled successfully for {username} "}
            else:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Could not update resource, twoFA already enabled")

    except Exception as err:
        if not isinstance(err, HTTPException):
            print(f"An error occured {str(err)}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')    
        else:
            raise


@app.put('/assign-role/', dependencies=[Depends(RoleManager.role_required('admin'))])
async def assign_role(request:Request, username:str = Form(...), role_name:str = Form(...)):

    try:        
        # first check if the user exists 
        with DatabaseManager() as db:
            query_user = "SELECT * FROM users WHERE username = %s"
            params_user = (username,)

            result = db.execute_read(query_user, params_user)

        # if user not found
        if not result:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found")
        
        # Now check if the role_name in roles table and get the role_id
        with DatabaseManager() as db:
            query_role = "SELECT role_id FROM roles WHERE role_name = %s"
            params_role = (role_name,)
            role_id = db.execute_read(query_role, params_role)

        if not role_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="role_name not found")
        
        role_id = role_id.get('role_id')
        
        # now update the role id to the users table role_id column

        with DatabaseManager() as db:
            update_query_role = "UPDATE users SET role_id = %s WHERE username = %s"
            update_params_role = (role_id, username)
            update_result = db.execute_manipulation(update_query_role, update_params_role)


        if update_result == 1 :
            token = await TokenFactory.get_token_from_request(request)
            TokenManager.blacklist_token(username, token)

            return {"stat": "Ok",
                    "Result": f"'{role_name}' role_name for '{username}' updated successfully! "}
        
        else:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"'{role_name}' role already assigned!")
        
    except Exception as err:
        if not isinstance(err, HTTPException):
            print(f"An error occured {str(err)}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise



@app.get('/get-user-details/')
def get_user_details(username:str, current_user:None = Depends(TokenFactory.validate_token)):

    try:
        with DatabaseManager() as db:
            user_query = "SELECT * FROM users WHERE username = %s"
            user_param = (username,)

            is_user = db.execute_read(user_query, user_param)

        if not is_user:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found")

        with DatabaseManager() as db:
            details_query = '''
            SELECT u.username, u.email, r.role_name 
            FROM users u
            INNER JOIN roles r
            ON u.role_id = r.role_id
            WHERE u.username = %s
            '''

            details_params = (username,)

            result = db.execute_read(details_query, details_params)

        if not result:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found or role not assigned")
        
        return {'stat': 'Ok',
                'Result': result}
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            print(f"An error occured {str(err)}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise



@app.get('/users/me', response_model=Union[User])
def read_users_me(user:User=Depends(UserManager.get_current_user)):

    try:
        return user
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            print(f"An error occured {str(err)}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise

@app.post('/delete/user', response_model=Union[ClientResponse])
async def delete_user_me(request: Request, username:str = Form(...),
                   current_user:None = Depends(TokenFactory.validate_token)):    
    try:
        user = await UserManager.delete_user(username, request)
        return user
    
    except Exception as err:
        if not isinstance(err, HTTPException):
            print(f"An error occured {str(err)}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise

@app.post('/logout/', response_model=Union[ClientResponse])
async def logout_me(request:Request, 
                      username:str = Form(...),
                      current_user: None = Depends(TokenFactory.validate_token)):    
    try:
    
        user = await UserManager.logout_user(username, request)
        return user

    except Exception as err:
        if not isinstance(err, HTTPException):
            print(f"An error occured {str(err)}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Internal server error')
        else:
            raise



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

