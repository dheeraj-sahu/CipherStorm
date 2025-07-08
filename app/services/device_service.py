import requests
import uuid
from typing import Dict, Optional
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_location_data_from_ip(ip_address: str) -> Dict[str, Optional[str]]:
    """
    Get location data (country, city, latitude, longitude) from IP address
    using ipapi.co service
    """
    try:
        response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=5)
        response.raise_for_status()
        data = response.json()
        
        return {
            "country": data.get("country_name", "Unknown"),
            "city": data.get("city", "Unknown"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude")
        }
    except requests.RequestException as e:
        logger.error(f"Error fetching location data for IP {ip_address}: {e}")
        return {
            "country": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None
        }
    except Exception as e:
        logger.error(f"Unexpected error getting location data: {e}")
        return {
            "country": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None
        }

def get_client_ip_from_request(request) -> str:
    """
    Extract client IP address from ipapi.co service
    """
    try:
        response = requests.get("https://ipapi.co/json/", timeout=5)
        response.raise_for_status()
        data = response.json()
        
        ip_address = data.get("ip")
        if ip_address:
            return ip_address
        else:
            logger.warning("No IP address found in ipapi.co response")
            return "127.0.0.1"
            
    except requests.RequestException as e:
        logger.error(f"Error fetching IP from ipapi.co: {e}")
        return "127.0.0.1"
    except Exception as e:
        logger.error(f"Unexpected error getting IP address: {e}")
        return "127.0.0.1"

def get_device_id_from_request(request) -> str:
    """
    Extract device ID from request cookies or headers
    Device ID should be generated on frontend and sent via cookie/header
    """
    # Try to get device ID from cookie first
    device_id = request.cookies.get("device_id")
    
    # If not in cookie, try custom header
    if not device_id:
        device_id = request.headers.get("X-Device-ID")
    
    # If still not found, return a default/unknown identifier
    if not device_id:
        logger.warning("No device ID found in request")
        return "unknown_device"
    
    return device_id

def calculate_derived_columns(request) -> Dict:
    """
    Calculate all derived columns for a transaction
    """
    # Get device ID from request (generated on frontend)
    device_id = get_device_id_from_request(request)
    
    # Get client IP address
    ip_address = get_client_ip_from_request(request)
    
    # Get location data from IP
    location_data = get_location_data_from_ip(ip_address)
    
    return {
        "device_id": device_id,
        "ip_address": ip_address,
        "country": location_data["country"],
        "city": location_data["city"],
        "latitude": location_data["latitude"],
        "longitude": location_data["longitude"],
        "initiation_mode": "Default"  # Always set to Default as requested
    }