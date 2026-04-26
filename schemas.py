"""
schemas.py

Pydantic schemas for request and response validation.
"""
# schemas are for API request and response validation.
# They ensure data integrity and provide clear API contracts.
from pydantic import BaseModel, ConfigDict


class UserCreate(BaseModel):
    """
    Data required to create a user.
    """
    name: str
    role: str
    password: str


class UserResponse(BaseModel):
    """
    Data returned when user is created.
    """
    id: int
    name: str
    role: str

    model_config = ConfigDict(from_attributes=True)