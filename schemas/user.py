from pydantic import BaseModel
from typing import List, Optional

# User models
class UserBase(BaseModel):
    app_username: str

class UserCreate(UserBase):
    app_hashed_password: str

class User(UserBase):
    id: int

    class Config:
        orm_mode = True

# Vanguard Account models
class VanguardAccountBase(BaseModel):
    vanguard_username: str
    vanguard_encrypted_password: str

class VanguardAccountCreate(VanguardAccountBase):
    pass

class VanguardAccountUpdate(BaseModel):
    vanguard_username: Optional[str]
    vanguard_encrypted_password: Optional[str]

class VanguardAccount(VanguardAccountBase):
    id: int
    user_id: int

    class Config:
        orm_mode = True

# Vanguard login request
class VanguardLoginRequest(BaseModel):
    username: str
    password: str
    two_fa_code: Optional[str] = None
    action: Optional[str] = None

