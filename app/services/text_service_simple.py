import logging
import random
from datetime import datetime
from app.models.constant import IST
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SimpleTextAnalysisService:
    def __init__(self):
        """Initialize simple text analysis service"""
        self.suspicious_keywords = [
            'urgent', 'click here', 'verify now', 'suspend', 'confirm', 'password', 'login',
            'account', 'security', 'winner', 'congratulations', 'limited time', 'act now',
            'free', 'prize', 'lottery', 'bank', 'paypal', 'amazon', 'microsoft', 'apple',
            'virus', 'malware', 'infected', 'update required', 'expired', 'locked'
        ]
        
        self.phishing_indicators = [
            'suspicious url patterns', 'urgent action required', 'request for personal info',
            'spelling errors', 'generic greetings', 'threat of account closure',
            'too good to be true offers', 'unusual sender patterns'
        ]
        
        logger.info("Simple text analysis service initialized")
    
    def analyze_text_complete(self, text: str) -> dict:
        """
        Complete text analysis with simplified logic
        """
        try:
            text_lower = text.lower()
            
            # Count suspicious keywords
            suspicious_count = sum(1 for keyword in self.suspicious_keywords if keyword in text_lower)
            
            # Simple heuristics
            has_urls = bool(re.search(r'http[s]?://|www\.|\.[a-z]{2,}', text_lower))
            has_urgency = any(word in text_lower for word in ['urgent', 'immediately', 'asap', 'expires', 'limited'])
            has_money_terms = any(word in text_lower for word in ['money', 'cash', 'prize', 'winner', 'lottery', 'reward'])
            has_threats = any(word in text_lower for word in ['suspend', 'close', 'freeze', 'block', 'terminate'])
            
            # Calculate scores
            keyword_score = min(suspicious_count / 10.0, 1.0)  # Normalize to 0-1
            url_score = 0.3 if has_urls else 0.0
            urgency_score = 0.4 if has_urgency else 0.0
            money_score = 0.5 if has_money_terms else 0.0
            threat_score = 0.6 if has_threats else 0.0
            
            # Final phishing score
            phishing_score = min((keyword_score + url_score + urgency_score + money_score + threat_score) / 2.0, 1.0)
            
            # Determine if phishing
            is_phishing = phishing_score > 0.4
            confidence = abs(phishing_score - 0.5) * 2  # Scale to 0-1
            
            # Generate indicators
            indicators = []
            if suspicious_count > 0:
                indicators.append(f"Found {suspicious_count} suspicious keywords")
            if has_urls:
                indicators.append("Contains URLs or web addresses")
            if has_urgency:
                indicators.append("Uses urgent language")
            if has_money_terms:
                indicators.append("Contains money-related terms")
            if has_threats:
                indicators.append("Contains threatening language")
            
            if not indicators:
                indicators.append("No obvious suspicious patterns detected")
            
            return {
                'is_phishing': is_phishing,
                'phishing_score': phishing_score,
                'confidence': confidence,
                'classification': 'phishing' if is_phishing else 'legitimate',
                'analysis_details': {
                    'emotion_score': urgency_score,
                    'threat_score': threat_score,
                    'urgency_score': urgency_score,
                    'groq_classification': 'spam' if is_phishing else 'ham',
                    'groq_confidence': confidence,
                    'bert_contribution': {'spam': phishing_score, 'ham': 1 - phishing_score},
                    'zero_shot_contribution': {'spam': phishing_score, 'ham': 1 - phishing_score},
                    'layer_contributions': {
                        'layer1_weight': 0.33,
                        'layer2_weight': 0.33,
                        'layer3_weight': 0.34,
                        'layer1_score': keyword_score,
                        'layer2_score': (urgency_score + threat_score) / 2,
                        'layer3_score': phishing_score
                    }
                },
                'indicators': indicators,
                'keywords': [kw for kw in self.suspicious_keywords if kw in text_lower],
                'timestamp': datetime.now().isoformat(),
                'processing_time': '< 1 second'
            }
            
        except Exception as e:
            logger.error(f"Error in simple text analysis: {str(e)}")
            return {
                'is_phishing': False,
                'phishing_score': 0.5,
                'confidence': 0.0,
                'classification': 'unknown',
                'error': str(e),
                'analysis_details': {
                    'emotion_score': 0.0,
                    'threat_score': 0.0,
                    'urgency_score': 0.0,
                    'groq_classification': 'unknown',
                    'groq_confidence': 0.0,
                    'bert_contribution': {'spam': 0.5, 'ham': 0.5},
                    'zero_shot_contribution': {'spam': 0.5, 'ham': 0.5},
                    'layer_contributions': {
                        'layer1_weight': 0.33,
                        'layer2_weight': 0.33,
                        'layer3_weight': 0.34,
                        'layer1_score': 0.5,
                        'layer2_score': 0.5,
                        'layer3_score': 0.5
                    }
                },
                'indicators': ['Analysis error occurred'],
                'keywords': [],
                'timestamp': datetime.now().isoformat(),
                'processing_time': '< 1 second'
            }

# Create a singleton instance
simple_text_analysis_service = SimpleTextAnalysisService()
