from pydantic import BaseModel
from typing import Optional

class ProfileCreate(BaseModel):
    full_name:str
    mobile_no:str
    upi_id:str
    address: Optional[str]=None
    transaction_limit:Optional[float]=10000.00
    