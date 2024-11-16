from dotenv import load_dotenv
import smtplib
import os
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

        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        
        logging.info("OTP email sent successfully!")

    except Exception as e:
        logging.info("Failed to send OTP email!")
        logging.error(f"Error occured at send_otp_email : {str(e)}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal Server Error")
    

async def send_password_reset_email(recepient:str, link:str):

    try:
        msg = EmailMessage()
        msg["Subject"] = "Password reset for AuthApp service"
        msg["From"]    = f"AuthSphere<{EMAIL_FROM}>"
        msg["To"]      = f"{recepient}<{recepient}>"
        msg.set_content(f"Hi, Your password reset link: {link}")

        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        
        logging.info("Password reset email sent successfully!")

    except Exception as e:
        logging.info("Failed to send reset email!")
        logging.error(f"Error occured at send_password_reset_email : {str(e)}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal Server Error")

    