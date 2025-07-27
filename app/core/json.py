"""Custom JSON encoder for UUID and other types."""

import json
import uuid
from datetime import datetime, date
from decimal import Decimal
from enum import Enum
from pathlib import Path


class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for UUID, exceptions, and other types."""
    
    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            return str(obj)
        elif isinstance(obj, (datetime, date)):
            return obj.isoformat()
        elif isinstance(obj, Decimal):
            return float(obj)
        elif isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, Path):
            return str(obj)
        elif isinstance(obj, Exception):
            # Handle exceptions by converting to dict
            return {
                "error_type": obj.__class__.__name__,
                "error_message": str(obj),
                "args": obj.args
            }
        elif hasattr(obj, '__dict__'):
            # Handle objects with __dict__ (like custom classes)
            return obj.__dict__
        return super().default(obj)


def custom_json_serializer(obj):
    """Custom JSON serializer function for FastAPI."""
    return json.dumps(obj, cls=CustomJSONEncoder, ensure_ascii=False)