import os
import json
import re
import time
from typing import List, Dict
from dataclasses import dataclass
from dotenv import load_dotenv
from groq import Groq
import requests
from bs4 import BeautifulSoup
import phonenumbers
from phonenumbers import geocoder, carrier
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

@dataclass
class VerificationResult:
    phone_number: str
    company_name: str
    risk_score: int
    risk_level: str
    confidence: int
    number_type: str
    toll_free: bool
    landline: bool
    mobile: bool
    numbers_found_in_sources: int
    risk_details: List[str]
    recommendation: str
    found_numbers: List[str]
    enhanced_info: dict = None

# Phone number extraction regex
PHONE_REGEX = re.compile(
    r'(?:'
    r'(?:\+?\d{1,3}[\s\-]?)?'  # Optional country code
    r'(?:\(?\d{2,5}\)?[\s\-]?)?'  # Optional area code
    r'\d{3,4}[\s\-]?\d{4,5}'  # Main number
    r'|'
    r'1800[\s\-]?\d{2,4}(?:[\s\-]?\d{2,4})?'  # Toll-free numbers
    r'|'
    r'18\d{2}[\s\-]?\d{3,4}[\s\-]?\d{3,4}'  # Other toll-free variations
    r')'
)

def normalize_phone_number(phone: str) -> str:
    """Normalize phone number by removing spaces, hyphens, and other formatting"""
    return ''.join(filter(str.isdigit, phone))

def extract_phone_numbers(text: str) -> List[str]:
    """Extract phone numbers from text using regex pattern"""
    if not text:
        return []
    
    matches = PHONE_REGEX.findall(text)
    
    cleaned_numbers = []
    seen = set()
    
    for match in matches:
        cleaned = match.strip()

        digits_only = re.sub(r'[^\d]', '', cleaned)
        is_toll_free = digits_only.startswith(('1800', '18'))
        
        if ((is_toll_free and len(digits_only) >= 7) or 
        (not is_toll_free and len(digits_only) >= 10)) and cleaned not in seen:
            cleaned_numbers.append(cleaned)
            seen.add(cleaned)
    
    return cleaned_numbers

def fetch_visible_text(url: str, max_retries: int = 3) -> str:
    """Fetch visible text from a URL with error handling and retries"""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
        )
    }

    for attempt in range(max_retries):
        try:
            logger.info(f"Fetching URL (attempt {attempt + 1}/{max_retries}): {url}")
            
            # Add delay between attempts
            if attempt > 0:
                time.sleep(2 ** attempt)  # Exponential backoff
            
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()

            soup = BeautifulSoup(resp.text, "html.parser")

            for tag in soup(["script", "style", "noscript", "header", "footer"]):
                tag.decompose()

            text = soup.get_text(separator="\n")
            logger.info(f"Successfully fetched {len(text)} characters from {url}")
            return text
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                logger.warning(f"403 Forbidden for {url} - trying different approach")
                # Try with different headers
                headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                continue
            elif e.response.status_code == 429:
                logger.warning(f"Rate limited for {url} - waiting longer")
                time.sleep(5 * (attempt + 1))
                continue
            else:
                logger.error(f"HTTP Error {e.response.status_code} for {url}: {e}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {url} (attempt {attempt + 1}): {e}")
            
        except Exception as e:
            logger.error(f"Unexpected error fetching {url}: {e}")
    
    logger.warning(f"Failed to fetch {url} after {max_retries} attempts")
    return ""

def chunk_text(text: str, chunk_size: int = 1000, overlap: int = 200) -> List[str]:
    """Split text into overlapping chunks for better context preservation"""
    if not text:
        return []
    
    chunks = []
    start = 0
    
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        
        if end < len(text) and not chunk.endswith(' '):
            last_space = chunk.rfind(' ')
            if last_space > start + chunk_size // 2:
                end = start + last_space
                chunk = text[start:end]
        
        chunks.append(chunk.strip())
        start = end - overlap
        if start >= len(text):
            break
    
    return [chunk for chunk in chunks if chunk]

def get_llm_strategy(phone_list: List[str]) -> str:
    """Generate LLM strategy for phone number filtering"""
    instruction = (
        "Extract ALL legitimate customer service phone numbers from website content.\n"
        f"Phone numbers found: {phone_list}\n"
        "Include ALL numbers that could be customer service related:\n"
        "- Must be 10+ digits long (or 7+ digits for toll-free numbers like 1800-XXXX)\n"
        "- Toll-free numbers (1800, 800, etc.)\n"
        "- Numbers labeled as 'customer care', 'support', 'helpline', 'contact', 'partnership', 'legal'\n"
        "- Numbers under city/location names (these are regional customer service)\n"
        "- Numbers under department names (legal, partnership, etc.)\n"
        "- Numbers from company contact pages or customer service pages\n"
        "EXCLUDE ONLY:\n"
        "-Numbers with less than 10 digits (except toll-free numbers which can be 7+ digits)\n"
        "- Numbers that are clearly dates, IDs, or codes (like 2024, 1234, etc.)\n"
        "When in doubt, INCLUDE the number. Return ALL valid customer service numbers."
    )
    return instruction

def filter_customer_care_numbers(chunks: List[str], phone_relation: dict, max_retries: int = 2) -> List[str]:
    """Filter customer care numbers using LLM with error handling"""
    filtered = []
    
    try:
        client = Groq(api_key=os.getenv("GROQ_API_KEY"),max_retries=0)
    except Exception as e:
        logger.error(f"Failed to initialize Groq client: {e}")
        return []

    for chunk, phones in phone_relation.items():
        instruction = get_llm_strategy(phones)
        input_text = chunk[:2000]
        
        prompt = f"{instruction}\n\nText: {input_text}\n\nReturn only valid JSON in this format: {{\"customer_numbers\": [\"phone1\", \"phone2\"]}}"

        for attempt in range(max_retries):
            try:
                logger.info(f"Sending chunk to LLM (attempt {attempt + 1}/{max_retries})")
                
                # Add delay between API calls
                if attempt > 0:
                    # Exponential backoff with initial 5 second delay
                    time.sleep(5 * (2 ** attempt))  # 5s, 10s, 20s for retries
                
                response = client.chat.completions.create(
                    model="deepseek-r1-distill-llama-70b",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                    max_tokens=1000
                )
                
                result_text = response.choices[0].message.content.strip()
                
                if not result_text:
                    logger.warning("Empty response from LLM")
                    continue
                
                # Extract JSON from DeepSeek response
                if "<think>" in result_text and "</think>" in result_text:
                    json_start = result_text.find("</think>") + 8
                    result_text = result_text[json_start:].strip()
                
                # Clean up markdown formatting
                if result_text.startswith('json'):
                    result_text = result_text[7:-3].strip()
                elif result_text.startswith('```'):
                    result_text = result_text[3:-3].strip()
                
                # If we get a partial JSON starting with "ustomer_numbers", add the missing part
                if result_text.startswith('ustomer_numbers'):
                    result_text = '{"c' + result_text
                
                # Fix incomplete JSON
                if not result_text.startswith('{'):
                    result_text = '{' + result_text
                
                if result_text.count('"') % 2 != 0:
                    last_complete = result_text.rfind('", "')
                    if last_complete != -1:
                        result_text = result_text[:last_complete + 1] + ']}'
                    else:
                        if result_text.endswith('"'):
                            result_text += ']}'
                        elif result_text.endswith('['):
                            result_text += ']}'
                
                # Make sure the JSON is properly closed
                if not result_text.endswith('}'):
                    if result_text.endswith('"'):
                        result_text += ']}'
                    elif result_text.endswith('['):
                        result_text += ']}'
                    elif result_text.endswith(','):
                        result_text = result_text.rstrip(',') + ']}'
                
                result = json.loads(result_text)
                if result and "customer_numbers" in result:
                    filtered.extend(result["customer_numbers"])
                    logger.info(f"Successfully extracted {len(result['customer_numbers'])} numbers")
                    break  # Success, exit retry loop
                    
            except json.JSONDecodeError as e:
                logger.error(f"JSON parsing error (attempt {attempt + 1}): {e}")
                logger.error(f"Response was: {result_text}")
                
            except Exception as e:
                if "rate limit" in str(e).lower() or "429" in str(e):
                    logger.warning(f"Rate limited by LLM API (attempt {attempt + 1}): {e}")
                    time.sleep(10 * (attempt + 1))  # Longer wait for rate limits
                else:
                    logger.error(f"LLM extraction error (attempt {attempt + 1}): {e}")
                    
        # Add larger delay between chunks to respect rate limits
        time.sleep(5)  # 10 second delay between chunks to avoid rate limits

    # Remove duplicates
    seen_normalized = set()
    unique_filtered = []
    
    for number in filtered:
        normalized = normalize_phone_number(number)
        is_toll_free = normalized.startswith('1800')
        if ((is_toll_free and len(normalized) >= 7) or  # Allow toll-free numbers ≥ 7 digits
            (not is_toll_free and len(normalized) >= 10)) and normalized not in seen_normalized:
            seen_normalized.add(normalized)
            unique_filtered.append(number)
    
    return unique_filtered

def google_search(query, num_results=6, max_retries=2):
    """Search Google CSE for URLs with error handling"""
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
    GOOGLE_CSE_ID = os.getenv("GOOGLE_CSE_ID")
    
    if not GOOGLE_API_KEY or not GOOGLE_CSE_ID:
        logger.error("Google API key or CSE ID not found")
        return []
    
    results = []
    start = 0
    
    while len(results) < num_results:
        url = "https://www.googleapis.com/customsearch/v1"
        params = {
            "q": query,
            "key": GOOGLE_API_KEY,
            "cx": GOOGLE_CSE_ID,
            "start": start + 1
        }
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Google search (attempt {attempt + 1}): {query}")
                
                if attempt > 0:
                    time.sleep(2 ** attempt)
                
                res = requests.get(url, params=params, timeout=15)
                res.raise_for_status()
                
                data = res.json()
                
                if "error" in data:
                    logger.error(f"Google API error: {data['error']}")
                    return results
                
                items = data.get("items", [])
                results.extend([item["link"] for item in items])
                
                if not items or len(items) < 10:
                    return results[:num_results]
                    
                start += 10
                break  # Success, exit retry loop
                
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    logger.warning(f"Google API rate limited (attempt {attempt + 1})")
                    time.sleep(10 * (attempt + 1))
                else:
                    logger.error(f"Google search HTTP error: {e}")
                    
            except Exception as e:
                logger.error(f"Google search error (attempt {attempt + 1}): {e}")
                
        # Add delay between search pages
        time.sleep(1)
    
    return results[:num_results]

def get_company_numbers_internal(company_name: str) -> List[str]:
    """Get all customer care numbers for a company with error handling"""
    company_name = company_name.lower()
    
    # First check pissedconsumer URL
    pissed_url = f"https://{company_name}.pissedconsumer.com/customer-service.html"
    logger.info(f"Checking pissedconsumer URL: {pissed_url}")
    
    all_chunks = []
    phone_relation = {}
    
    try:
        text = fetch_visible_text(pissed_url)
        if text:
            numbers = extract_phone_numbers(text)
            if numbers:
                chunks = chunk_text(text)
                for ch in chunks:
                    matched_phones = [num for num in numbers if num in ch]
                    if matched_phones:
                        phone_relation[ch] = matched_phones
                all_chunks.extend(chunks)
                logger.info(f"Found {len(numbers)} numbers from pissedconsumer")
    except Exception as e:
        logger.error(f"Error processing pissedconsumer URL: {e}")
    
    # Search Google CSE for other URLs
    query = f"{company_name} customer care number india customer care"
    logger.info(f"Searching Google for: {query}")
    
    urls = google_search(query, num_results=10)  # Reduced to process only first 10 URLs
    logger.info(f"Found {len(urls)} URLs to process")
    
    for i, url in enumerate(urls):
        try:
            logger.info(f"Processing URL {i+1}/{len(urls)}: {url}")
            
            text = fetch_visible_text(url)
            if not text:
                continue
                
            numbers = extract_phone_numbers(text)
            if not numbers:
                continue
                
            chunks = chunk_text(text)
            for ch in chunks:
                matched_phones = [num for num in numbers if num in ch]
                if matched_phones:
                    phone_relation[ch] = matched_phones
            all_chunks.extend(chunks)
            
            # Add delay between URL processing
            time.sleep(1)
            
        except Exception as e:
            logger.error(f"Error processing {url}: {e}")
            continue
    
    logger.info(f"Sending {len(phone_relation)} chunks to LLM for filtering")
    filtered = filter_customer_care_numbers(all_chunks, phone_relation)
    logger.info(f"Final filtered numbers: {len(filtered)}")
    
    return filtered

def analyze_phone_number(phone_number: str) -> dict:
    """Analyze phone number type and characteristics"""
    cleaned = normalize_phone_number(phone_number)
    
    # Handle country code for analysis (but keep original for NumVerify)
    analysis_number = cleaned
    if cleaned.startswith('91') and len(cleaned) >= 12:
        analysis_number = cleaned[2:]  # Remove country code for analysis
    elif cleaned.startswith('91') and len(cleaned) == 10 and cleaned[2:].startswith('1800'):
        analysis_number = cleaned[2:]  # Remove country code for 1800 numbers specifically
    
    return {
        'toll_free': analysis_number.startswith('1800'),
        'landline': len(analysis_number) == 11 and not analysis_number.startswith(('9', '8', '7', '6')),
        'mobile': len(analysis_number) == 10 and analysis_number.startswith(('9', '8', '7', '6')),
        'number_type': 'Toll-Free' if analysis_number.startswith('1800') else
                       'Mobile' if len(analysis_number) == 10 and analysis_number.startswith(('9', '8', '7', '6')) else
                       'Landline' if len(analysis_number) == 11 else 'Unknown'
    }

def get_basic_info(phone_number):
    """Get basic phone number information using phonenumbers library"""
    try:
        if not phone_number.startswith('+'):
            phone_number = '+91' + phone_number.lstrip('0')
        
        number = phonenumbers.parse(phone_number)
        region = geocoder.description_for_number(number, "en")
        network = carrier.name_for_number(number, "en")
        
        return {
            "valid": phonenumbers.is_valid_number(number),
            "region": region if region else "Unknown",
            "carrier": network if network else "Unknown",
            "country_code": number.country_code,
            "national_number": number.national_number
        }
    except Exception as e:
        logger.error(f"Error getting basic phone info: {e}")
        return {"error": str(e)}

def numverify_lookup(phone_number):
    """Lookup phone number using NumVerify API"""
    key = os.getenv("NUMVERIFY_API_KEY")
    if not key:
        return {"error": "NumVerify API key not found"}
    
    clean_number = phone_number.replace('+', '').replace(' ', '').replace('-', '')
    url = f"http://apilayer.net/api/validate?access_key={key}&number={clean_number}"
    
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
        return res.json()
    except Exception as e:
        logger.error(f"NumVerify lookup error: {e}")
        return {"error": str(e)}

def get_enhanced_phone_info(phone_number):
    """Get comprehensive phone number information"""
    basic_info = get_basic_info(phone_number)
    numverify_info = numverify_lookup(phone_number)
    
    return {
        "basic_info": basic_info,
        "numverify_info": numverify_info
    }

def calculate_risk_score(user_number: str, company_name: str, found_numbers: List[str], enhanced_info: dict = None) -> VerificationResult:
    """Calculate risk score for the user's phone number"""
    normalized_user = normalize_phone_number(user_number)

     # Handle country code for matching
    user_for_matching = normalized_user
    if normalized_user.startswith('91') and len(normalized_user) == 10:
        user_for_matching = normalized_user[2:]  # Remove 91 for matching
        print(f"DEBUG: User for matching (after removing 91): {user_for_matching}")


    normalized_found = list({normalize_phone_number(num) for num in found_numbers})
    
    # Check if number exists in found numbers
    number_found = False
    exact_match = False
    
    for num in normalized_found:
        if user_for_matching == num:
            number_found = True
            exact_match = True
            break
        elif user_for_matching.startswith('1800') and num.startswith('1800') and user_for_matching[-4:] == num[-4:]:
            number_found = True
            break
    
    # Begin scoring logic
    risk_score = 0
    confidence = 0
    risk_details = []
    
    # Primary factor: Number found in sources
    if number_found:
        if exact_match:
            risk_score += 5
            confidence += 70
            risk_details.append("✅ Exact match found in customer care sources")
        else:
            risk_score += 15
            confidence += 50
            risk_details.append("✅ Similar number found in customer care sources")
    else:
        risk_score += 75
        confidence += 25
        risk_details.append("❌ Number NOT found in known customer care sources")
    
    # Source count factor
    if len(found_numbers) >= 10:
        confidence += 25
        risk_details.append(f"✅ {len(found_numbers)} numbers found across multiple sources")
    elif len(found_numbers) >= 5:
        confidence += 15
        risk_details.append(f"✅ {len(found_numbers)} numbers found in sources")
    else:
        risk_score += 20
        confidence -= 10
        risk_details.append(f"⚠ Only {len(found_numbers)} numbers found in sources")
    
    # Number type analysis
    phone_analysis = analyze_phone_number(user_number)
    
    if phone_analysis['toll_free']:
        risk_score -= 15
        confidence += 15
        risk_details.append("✅ Toll-Free number detected - generally legitimate")
    elif phone_analysis['mobile']:
        risk_score += 10
        risk_details.append("⚠ Mobile number - less common for customer care")
    elif phone_analysis['landline']:
        risk_score -= 5
        risk_details.append("✅ Landline number - common for customer care")
    
    # Length validation
    if len(normalized_user) < 10:
        risk_score += 30
        confidence -= 20
        risk_details.append("❌ Number too short - likely invalid")
    elif len(normalized_user) > 12:
        risk_score += 20
        confidence -= 10
        risk_details.append("⚠ Number unusually long")
    
    # Clamp scores to valid ranges
    risk_score = max(0, min(100, risk_score))
    confidence = max(0, min(100, confidence))
    
    # Determine risk level
    if risk_score <= 25:
        risk_level = "LOW"
    elif risk_score <= 55:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"
    
    # Generate recommendation
    if risk_level == "LOW":
        recommendation = "✅ RECOMMENDATION: This appears to be a LEGITIMATE customer care number"
    elif risk_level == "MEDIUM":
        recommendation = "⚠ RECOMMENDATION: EXERCISE CAUTION - verify through official channels before calling"
    else:
        recommendation = "❌ RECOMMENDATION: HIGH RISK - likely NOT a legitimate customer care number. Do not call."
    
    return VerificationResult(
        phone_number=user_number,
        company_name=company_name,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=confidence,
        number_type=phone_analysis['number_type'],
        toll_free=phone_analysis['toll_free'],
        landline=phone_analysis['landline'],
        mobile=phone_analysis['mobile'],
        numbers_found_in_sources=len(found_numbers),
        risk_details=risk_details,
        recommendation=recommendation,
        found_numbers=found_numbers,
        enhanced_info=enhanced_info
    )

def verify_phone_number(company_name: str, user_number: str) -> VerificationResult:
    """Main verification function with comprehensive error handling"""
    try:
        logger.info(f"Starting verification for {company_name} - {user_number}")
        
        # Get all customer care numbers for the company
        found_numbers = get_company_numbers_internal(company_name)
        
        if not found_numbers:
            logger.warning(f"No customer care numbers found for {company_name}")
            # Return high risk result if no numbers found
            return VerificationResult(
                phone_number=user_number,
                company_name=company_name,
                risk_score=90,
                risk_level="HIGH",
                confidence=20,
                number_type="Unknown",
                toll_free=False,
                landline=False,
                mobile=False,
                numbers_found_in_sources=0,
                risk_details=["❌ No customer care numbers found for this company"],
                recommendation="❌ RECOMMENDATION: HIGH RISK - No legitimate customer care numbers found for this company.",
                found_numbers=[],
                enhanced_info=None
            )
        
        # Get enhanced phone information
        enhanced_info = get_enhanced_phone_info(user_number)
        
        # Calculate risk score and verify
        result = calculate_risk_score(user_number, company_name, found_numbers, enhanced_info)
        
        logger.info(f"Verification complete - Risk Level: {result.risk_level}, Score: {result.risk_score}")
        return result
        
    except Exception as e:
        logger.error(f"Error in verification process: {e}")
        # Return error result
        return VerificationResult(
            phone_number=user_number,
            company_name=company_name,
            risk_score=95,
            risk_level="HIGH",
            confidence=10,
            number_type="Unknown",
            toll_free=False,
            landline=False,
            mobile=False,
            numbers_found_in_sources=0,
            risk_details=[f"❌ Error during verification: {str(e)}"],
            recommendation="❌ RECOMMENDATION: HIGH RISK - Verification failed due to technical error.",
            found_numbers=[],
            enhanced_info=None
        )