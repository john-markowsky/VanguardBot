from sqlalchemy.orm import Session
from passlib.context import CryptContext
from secure import encrypt_data, decrypt_data
from keys import ENCRYPTION_KEY
import models.db_models as db_models


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_user_by_username(db: Session, username: str):
    return db.query(db_models.User).filter(db_models.User.app_username == username).first()

def get_user_by_id(db: Session, user_id: int):
    return db.query(db_models.User).filter(db_models.User.id == user_id).first()

def get_password_hash(password: str):
    return pwd_context.hash(password)

def create_vanguard_account(db: Session, username: str, password: str, user_id: int):
    encrypted_username = encrypt_data(username, ENCRYPTION_KEY)
    encrypted_password = encrypt_data(password, ENCRYPTION_KEY)
    vanguard_account = db_models.VanguardAccount(
        vanguard_username=encrypted_username,
        vanguard_encrypted_password=encrypted_password, 
        user_id=user_id
    )
    db.add(vanguard_account)
    db.commit()
    db.refresh(vanguard_account)
    return vanguard_account

def get_vanguard_accounts_for_user(db: Session, user_id: int):
    vanguard_accounts = db.query(db_models.VanguardAccount).filter(db_models.VanguardAccount.user_id == user_id).all()
    for account in vanguard_accounts:
        account.vanguard_username = decrypt_data(account.vanguard_username, ENCRYPTION_KEY)
        account.vanguard_encrypted_password = decrypt_data(account.vanguard_encrypted_password, ENCRYPTION_KEY)
    return vanguard_accounts

def delete_vanguard_account(db: Session, vanguard_account_id: int):
    vanguard_account = db.query(db_models.VanguardAccount).filter(db_models.VanguardAccount.id == vanguard_account_id).first()
    if vanguard_account:
        db.delete(vanguard_account)
        db.commit()
        return True
    return False

def get_encrypted_password(password: str):
    return pwd_context.hash(password)

def verify_encrypted_password(encrypted_password: str, entered_password: str):
    return pwd_context.verify(entered_password, encrypted_password)