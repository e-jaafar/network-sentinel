#!/usr/bin/env python3
"""
Authentication module for Network Sentinel
Simple JWT-based auth with a single admin user
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# Security
security = HTTPBearer(auto_error=False)


class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class LoginRequest(BaseModel):
    username: str
    password: str


class User(BaseModel):
    username: str


# Default admin credentials
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD_HASH = hashlib.sha256("sentinel".encode()).hexdigest()


def hash_password(password: str) -> str:
    """Hash a password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return hash_password(plain_password) == hashed_password


async def get_admin_credentials() -> tuple[str, str]:
    """Get admin credentials from database or use defaults"""
    from database import get_setting
    
    username = await get_setting("admin_username") or DEFAULT_USERNAME
    password_hash = await get_setting("admin_password_hash") or DEFAULT_PASSWORD_HASH
    
    return username, password_hash


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt


async def authenticate_user(username: str, password: str) -> Optional[User]:
    """Authenticate a user with username and password"""
    admin_username, admin_password_hash = await get_admin_credentials()
    
    if username != admin_username:
        return None
    
    if not verify_password(password, admin_password_hash):
        return None
    
    return User(username=username)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> User:
    """Dependency to get the current authenticated user"""
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if credentials is None:
        raise credentials_exception
    
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if username is None:
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
    
    return User(username=username)


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[User]:
    """Dependency to optionally get the current user (doesn't fail if not authenticated)"""
    
    if credentials is None:
        return None
    
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if username is None:
            return None
            
        return User(username=username)
        
    except JWTError:
        return None
