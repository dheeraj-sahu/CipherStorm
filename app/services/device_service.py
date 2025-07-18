import requests
import uuid
from typing import Dict, Optional, Tuple
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_ip_and_location_data(request=None) -> Tuple[str, Dict[str, Optional[str]]]:
    """
    Get both IP address and location data, properly handling forwarded IPs in AWS
    """
    try:
        # Get the real client IP address
        if request:
            # Try to get IP from X-Forwarded-For header first (AWS ALB/CloudFront adds this)
            forwarded_for = request.headers.get('X-Forwarded-For')
            if forwarded_for:
                # X-Forwarded-For can contain multiple IPs, first one is the client
                client_ip = forwarded_for.split(',')[0].strip()
            else:
                # Try other common headers
                client_ip = (request.headers.get('X-Real-IP') or
                           request.headers.get('CF-Connecting-IP') or  # Cloudflare
                           request.headers.get('True-Client-IP') or    # Akamai
                           request.client.host)
        else:
            # Fallback to direct IP lookup if no request object
            direct_ip_response = requests.get("https://api.ipify.org?format=json", timeout=5)
            direct_ip_response.raise_for_status()
            client_ip = direct_ip_response.json().get('ip', '127.0.0.1')

        # Get location data for the client IP
        location_response = requests.get(f"https://ipapi.co/{client_ip}/json/", timeout=5)
        location_response.raise_for_status()
        data = location_response.json()
        
        location_data = {
            "country": data.get("country_name", "Unknown"),
            "city": data.get("city", "Unknown"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude")
        }
        
        logger.info(f"Successfully retrieved location data: IP={client_ip}, Country={location_data['country']}")
        return client_ip, location_data
        
    except requests.RequestException as e:
        logger.error(f"Error fetching location data: {e}")
        return "127.0.0.1", {
            "country": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None
        }
    except Exception as e:
        logger.error(f"Unexpected error getting IP and location data: {e}")
        return "127.0.0.1", {
            "country": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None
        }

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
    
    # Get IP and location data, passing the request object
    ip_address, location_data = get_ip_and_location_data(request)
    
    return {
        "device_id": device_id,
        "ip_address": ip_address,
        "country": location_data["country"],
        "city": location_data["city"],
        "latitude": location_data["latitude"],
        "longitude": location_data["longitude"],
        "initiation_mode": "Default"  # Always set to Default as requested
    }