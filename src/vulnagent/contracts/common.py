"""PUBLIC CONTRACT: shared primitives."""
from datetime import datetime, timezone
from pydantic import BaseModel

def utc_now() -> datetime:
    """Return an aware UTC timestamp."""
    return datetime.now(timezone.utc)

class ContractModel(BaseModel):
    """Base for stable public DTOs."""
    model_config = {"extra": "ignore"}
