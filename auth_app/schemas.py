from pydantic import BaseModel, Field


class User(BaseModel):
    username: str
    email: str

class UserCreate(User):
    password: str
    twoFA_enabled: bool = False
    role_id : int = 2


class ClientResponse(BaseModel):
    stat   :   str
    Result :   str
