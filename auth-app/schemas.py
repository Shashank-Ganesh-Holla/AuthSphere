from pydantic import BaseModel, Field


class User(BaseModel):
    username: str
    email: str

class UserCreate(User):
    password: str
    twoFA_enabled: bool = False


class ClientResponse(BaseModel):
    stat   :   str
    Result :   str
