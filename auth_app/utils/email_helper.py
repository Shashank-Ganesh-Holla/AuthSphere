from dotenv import load_dotenv
import smtplib
import os
import aiosmtplib
from email.message import EmailMessage
import logging
from fastapi import HTTPException, status

load_dotenv()

EMAIL_HOST = os.getenv('EMAIL_HOST')
EMAIL_PORT = os.getenv('EMAIL_PORT')
EMAIL_USER  = os.getenv('EMAIL_USER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
EMAIL_FROM    = os.getenv('EMAIL_FROM')


async def send_otp_email(recepient:str, otp:str):

    try:
        msg = EmailMessage()
        msg["Subject"] = "Your OTP for AuthApp service"
        msg["From"]    = f"AuthSphere<{EMAIL_FROM}>"
        msg["To"]      = f"{recepient}<{recepient}>"
        msg.set_content(f"Hi, Your OTP code is {otp}")

        await aiosmtplib.send(
            msg,     # here the message is the position only parameter 
                        #so it should never be assigned as a keyword argument(refer aiosmtplib.send() for the '/' presence)
            hostname=EMAIL_HOST,
            port=EMAIL_PORT,
            start_tls=True,
            username=EMAIL_USER,
            password=EMAIL_PASSWORD,
        )
        
        logging.info("OTP email sent successfully!")


    except Exception as er:
        if not isinstance(er, HTTPException):
            logging.warning("Failed to send OTP email!")
            logging.error(f"Error occured: {str(er)}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
        else:
            raise

    

async def send_password_reset_email(recepient:str, link:str):

    try:
        msg = EmailMessage()
        msg["Subject"] = "Password reset for AuthApp service"
        msg["From"]    = f"AuthSphere<{EMAIL_FROM}>"
        msg["To"]      = f"{recepient}<{recepient}>"
        msg.set_content(f"Hi, Your password reset link: {link}")

        await aiosmtplib.send(
            msg,     # here the message is the position only parameter 
                        #so it should never be assigned as a keyword argument(refer aiosmtplib.send() for the '/' presence)
            hostname=EMAIL_HOST,
            port=EMAIL_PORT,
            start_tls=True,
            username=EMAIL_USER,
            password=EMAIL_PASSWORD,
        )
        
        logging.info("Password reset email sent successfully!")

    except Exception as er:
        if not isinstance(er, HTTPException):
            logging.warning("Failed to send OTP email!")
            logging.error(f"Error occured: {str(er)}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")
        else:
            raise

    