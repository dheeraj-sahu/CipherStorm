from pydantic import BaseModel
from typing import Optional

class ProfileCreate(BaseModel):
    full_name:str
    mobile_no:str
    upi_id:str
    country: Optional[str]="India"
    transaction_limit:Optional[float]=10000.00

class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    mobile_no: Optional[str] = None
    upi_id: Optional[str] = None
    country: Optional[str] = None
    transaction_limit: Optional[float] = None