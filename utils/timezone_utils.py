"""
Timezone utilities for converting UTC to Indian Standard Time (IST)
"""

from datetime import datetime, timezone, timedelta
from typing import Union, Optional


# Indian Standard Time timezone
IST = timezone(timedelta(hours=5, minutes=30))


def utc_to_ist(utc_datetime: datetime) -> datetime:
    """
    Convert UTC datetime to Indian Standard Time (IST)
    
    Args:
        utc_datetime: UTC datetime object
        
    Returns:
        IST datetime object
    """
    if utc_datetime.tzinfo is None:
        # Assume UTC if no timezone info
        utc_datetime = utc_datetime.replace(tzinfo=timezone.utc)
    
    return utc_datetime.astimezone(IST)


def format_ist_datetime(utc_datetime: datetime, format_string: str = "%d-%m-%Y %H:%M:%S") -> str:
    """
    Convert UTC datetime to IST and format as string
    
    Args:
        utc_datetime: UTC datetime object
        format_string: Format string for output
        
    Returns:
        Formatted IST datetime string
    """
    ist_datetime = utc_to_ist(utc_datetime)
    return ist_datetime.strftime(format_string)


def get_current_ist() -> datetime:
    """
    Get current time in IST
    
    Returns:
        Current IST datetime
    """
    return datetime.now(IST)


def get_current_ist_string(format_string: str = "%d-%m-%Y %H:%M:%S") -> str:
    """
    Get current time in IST as formatted string
    
    Args:
        format_string: Format string for output
        
    Returns:
        Formatted current IST datetime string
    """
    return get_current_ist().strftime(format_string)


def parse_ist_date_range(days_back: int) -> tuple[datetime, datetime]:
    """
    Generate date range for IST timezone
    
    Args:
        days_back: Number of days to go back
        
    Returns:
        Tuple of (start_date_utc, end_date_utc) for database queries
    """
    # Get current time in IST
    current_ist = get_current_ist()
    
    # Set end time to end of current day in IST
    end_ist = current_ist.replace(hour=23, minute=59, second=59, microsecond=999999)
    
    # Set start time to beginning of the day N days ago in IST
    start_ist = (current_ist - timedelta(days=days_back)).replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Convert to UTC for database queries
    start_utc = start_ist.astimezone(timezone.utc)
    end_utc = end_ist.astimezone(timezone.utc)
    
    return start_utc, end_utc


def format_excel_datetime(utc_datetime: Optional[datetime]) -> str:
    """
    Format datetime for Excel reports in IST
    
    Args:
        utc_datetime: UTC datetime object or None
        
    Returns:
        Formatted IST datetime string or empty string
    """
    if not utc_datetime:
        return ""
    
    if isinstance(utc_datetime, str):
        try:
            # Try to parse ISO format string
            utc_datetime = datetime.fromisoformat(utc_datetime.replace('Z', '+00:00'))
        except:
            return utc_datetime  # Return as-is if can't parse
    
    return format_ist_datetime(utc_datetime)


def format_excel_date(utc_datetime: Optional[datetime]) -> str:
    """
    Format date only for Excel reports in IST
    
    Args:
        utc_datetime: UTC datetime object or None
        
    Returns:
        Formatted IST date string or empty string
    """
    if not utc_datetime:
        return ""
    
    return format_ist_datetime(utc_datetime, "%d-%m-%Y")


def format_excel_time(utc_datetime: Optional[datetime]) -> str:
    """
    Format time only for Excel reports in IST
    
    Args:
        utc_datetime: UTC datetime object or None
        
    Returns:
        Formatted IST time string or empty string
    """
    if not utc_datetime:
        return ""
    
    return format_ist_datetime(utc_datetime, "%H:%M:%S")
