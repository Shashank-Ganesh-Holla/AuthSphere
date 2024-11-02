from pydantic import BaseModel, Field


class User(BaseModel):
    username: str
    email: str

class UserCreate(User):
    password: str
    role_id    : int
    twoFA_enabled: bool = False


class ClientResponse(BaseModel):
    stat   :   str
    Result :   str


    