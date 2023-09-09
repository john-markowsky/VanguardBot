from sqlalchemy import Column, Integer, String, Float, create_engine, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, reconstructor
from sqlalchemy.ext.hybrid import hybrid_property
from pydantic import BaseModel

from secure import encrypt_data, decrypt_data
from keys import ENCRYPTION_KEY
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    app_username = Column(String, unique=True, index=True)
    app_hashed_password = Column(String)
    accounts = relationship("Account", back_populates="owner")
    vanguard_accounts = relationship("VanguardAccount", back_populates="user")

class VanguardAccount(Base):
    __tablename__ = "vanguard_accounts"

    id = Column(Integer, primary_key=True, index=True)
    _vanguard_username = Column("vanguard_username", String, unique=True)  # Actual encrypted data
    _vanguard_encrypted_password = Column("vanguard_encrypted_password", String)  # Actual encrypted data
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="vanguard_accounts")

    # Used for the in-memory unencrypted data
    __transient_vanguard_username = None
    __transient_vanguard_encrypted_password = None

    @reconstructor
    def init_on_load(self):
        """Decrypt data when an object is loaded from the database."""
        self.__transient_vanguard_username = decrypt_data(self._vanguard_username, ENCRYPTION_KEY)
        self.__transient_vanguard_encrypted_password = decrypt_data(self._vanguard_encrypted_password, ENCRYPTION_KEY)

    @hybrid_property
    def vanguard_username(self):
        return self.__transient_vanguard_username

    @vanguard_username.setter
    def vanguard_username(self, value):
        self.__transient_vanguard_username = value
        self._vanguard_username = encrypt_data(value, ENCRYPTION_KEY)

    @hybrid_property
    def vanguard_encrypted_password(self):
        return self.__transient_vanguard_encrypted_password

    @vanguard_encrypted_password.setter
    def vanguard_encrypted_password(self, value):
        self.__transient_vanguard_encrypted_password = value
        self._vanguard_encrypted_password = encrypt_data(value, ENCRYPTION_KEY)

class Account(Base):
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True, index=True)
    account_type = Column(String, index=True)
    account_number = Column(String, unique=True)
    total_value = Column(Float)
    user_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="accounts")
    equities = relationship("Equity", back_populates="account")

class Equity(Base):
    __tablename__ = "equities"

    id = Column(Integer, primary_key=True, index=True)
    ticker_symbol = Column(String, index=True)
    name = Column(String)
    price = Column(Float)
    shares = Column(Float)
    total_value = Column(Float)
    account_id = Column(Integer, ForeignKey("accounts.id"))
    account = relationship("Account", back_populates="equities")

class VanguardLoginData(BaseModel):
    username: str
    password: str
    user_id: str

class Vanguard2FAData(BaseModel):
    two_fa_code: str
    user_id: str