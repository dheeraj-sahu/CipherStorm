from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import torch
import logging
import os
from groq import Groq
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GroqSpamClassifier:
    def __init__(self, api_key=None):
        """
        Initialize Groq client
        Get your API key from: https://console.groq.com/keys
        """
        self.client = Groq(
            api_key=api_key or os.environ.get("GROQ_API_KEY")
        )
    
    def classify_message(self, text, model="llama3-8b-8192"):
        """
        Classify a message as spam or ham using Groq API
        
        Args:
            text (str): The message to classify
            model (str): Model to use - options: "llama3-8b-8192", "mixtral-8x7b-32768"
        
        Returns:
            dict: Classification result with confidence
        """
        
        # Craft a clear prompt for classification
        prompt = f"""
You are a spam detection system. Classify the following message as either "spam" or "ham" (legitimate).

Message: "{text}"

Analyze the message for:
- Suspicious URLs or links
- Promotional language
- Urgent/threatening tone
- Requests for personal information
- Poor grammar/spelling (if excessive)
- Unusual sender patterns

Respond with ONLY a JSON object in this format:
{{
    "classification": "spam" or "ham",
    "confidence": 0.0-1.0,
    "reason": "brief explanation"
}}
"""

        try:
            # Make API call
            chat_completion = self.client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                model=model,
                temperature=0.1,  # Low temperature for consistent classification
                max_tokens=150,
                top_p=1,
                stream=False,
                stop=None,
            )
            
            # Extract and parse response
            response_text = chat_completion.choices[0].message.content.strip()
            
            # Try to parse JSON response
            try:
                result = json.loads(response_text)
                return {
                    "classification": result.get("classification", "unknown"),
                    "confidence": result.get("confidence", 0.5),
                    "reason": result.get("reason", "No reason provided"),
                    "model_used": model
                }
            except json.JSONDecodeError:
                # Fallback parsing if JSON fails
                classification = "spam" if "spam" in response_text.lower() else "ham"
                return {
                    "classification": classification,
                    "confidence": 0.7,
                    "reason": "Parsed from text response",
                    "model_used": model,
                    "raw_response": response_text
                }
                
        except Exception as e:
            return {
                "classification": "error",
                "confidence": 0.0,
                "reason": f"API Error: {str(e)}",
                "model_used": model
            }

class TextAnalysisService:
    def __init__(self):
        """Initialize all the models for text analysis"""
        self.models_loaded = False
        
        try:
            # Layer 1: Phishing Detection Models
            # Fine-tuned BERT classifier (your trained model)
            self.bert_classifier = pipeline('text-classification', 
                                          model='app/ml_models/fine_tuned_bert',
                                          return_all_scores=False,  # Your model returns single prediction
                                          truncation=True, 
                                          max_length=512)
            
            # Zero-shot classifier
            self.zero_shot_classifier = pipeline('zero-shot-classification', 
                                               model='facebook/bart-large-mnli')
            
            # Layer 2: Emotion, Threat, and Urgency Analysis
            # Emotion classifier
            emotion_model_name = "hamzawaheed/emotion-classification-model"
            self.emotion_classifier = pipeline("text-classification", 
                                             model=emotion_model_name, 
                                             return_all_scores=True,
                                             truncation=True, 
                                             max_length=512)
            
            # Threat classifier
            threat_model_name = "HiddenKise/Kaviel-threat-text-classifier"
            threat_tokenizer = AutoTokenizer.from_pretrained(threat_model_name)
            threat_model = AutoModelForSequenceClassification.from_pretrained(threat_model_name)
            self.threat_classifier = pipeline("text-classification", 
                                            model=threat_model, 
                                            tokenizer=threat_tokenizer, 
                                            return_all_scores=True,
                                            truncation=True, 
                                            max_length=512)
            
            # Urgency classifier (using zero-shot)
            self.urgency_classifier = pipeline("zero-shot-classification", 
                                             model="facebook/bart-large-mnli")
            
            # Layer 3: Groq Classifier
            self.groq_classifier = GroqSpamClassifier()
            
            # Define labels and weights
            self.phishing_labels = ["spam", "ham"]  # Updated to match your model's labels
            self.zero_shot_labels = ["spam", "ham"]
            self.urgency_labels = ["Urgent", "Not Urgent"]
            self.threat_labels = [
                'Life Threat',
                'Online Scams',
                'Information Leakage'
            ]
            
            # Layer weights
            self.weight_bert = 0.30
            self.weight_zero_shot = 0.70
            
            self.models_loaded = True
            logger.info("Text analysis models loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
            logger.info("Falling back to Groq-only analysis")
            
            # Fallback: Only use Groq classifier
            try:
                self.groq_classifier = GroqSpamClassifier()
                self.models_loaded = False
                logger.info("Groq classifier loaded successfully as fallback")
            except Exception as groq_error:
                logger.error(f"Error loading Groq classifier: {str(groq_error)}")
                raise Exception("Failed to load any text analysis models")
    
    def analyze_text_layer1(self, text: str) -> dict:
        """
        Layer 1: Ensemble of fine-tuned BERT and zero-shot classifier
        """
        try:
            # BERT model prediction (your fine-tuned model)
            bert_output = self.bert_classifier(text)
            
            # Your model returns format: [{'label': 'spam', 'score': 0.9919440746307373}]
            if isinstance(bert_output, list):
                bert_result = bert_output[0]
            else:
                bert_result = bert_output
            
            bert_label = bert_result['label'].lower()
            bert_score = bert_result['score']
            
            # Create probability distribution
            bert_probs = {
                'spam': bert_score if bert_label == 'spam' else 1 - bert_score,
                'ham': 1 - bert_score if bert_label == 'spam' else bert_score
            }
            
            # Zero-shot prediction
            zero_shot_output = self.zero_shot_classifier(text, candidate_labels=self.zero_shot_labels)
            zero_shot_probs = dict(zip(zero_shot_output['labels'], zero_shot_output['scores']))
            zero_shot_probs = {label.lower(): score for label, score in zero_shot_probs.items()}
            
            # Weighted ensemble
            ensemble_probs = {
                'spam': self.weight_bert * bert_probs['spam'] + self.weight_zero_shot * zero_shot_probs['spam'],
                'ham': self.weight_bert * bert_probs['ham'] + self.weight_zero_shot * zero_shot_probs['ham']
            }
            
            # Final prediction for layer 1
            final_label = max(ensemble_probs, key=ensemble_probs.get)
            final_score = ensemble_probs[final_label]
            
            return {
                'label': final_label,
                'score': final_score,
                'phishing_probability': ensemble_probs.get('spam', 0),  # spam = phishing
                'details': {
                    'bert_probs': bert_probs,
                    'zero_shot_probs': zero_shot_probs,
                    'ensemble_probs': ensemble_probs
                }
            }
            
        except Exception as e:
            logger.error(f"Error in layer 1 analysis: {str(e)}")
            return {
                'label': 'ham',
                'score': 0.5,
                'phishing_probability': 0.5,
                'details': {'error': str(e)}
            }
    
    def analyze_text_layer2(self, text: str) -> dict:
        """
        Layer 2: Emotion, Threat, and Urgency analysis
        """
        try:
            # Emotion Analysis
            emotion_result = self.emotion_classifier(text)
            if isinstance(emotion_result[0], list):
                emotion_scores = emotion_result[0]
            else:
                emotion_scores = emotion_result
            
            emotions = {item['label']: item['score'] for item in emotion_scores}
            emotion_score = (
                emotions.get('LABEL_3', 0) + 
                emotions.get('LABEL_4', 0) + 
                0.5 * emotions.get('LABEL_5', 0) + 
                0.3 * emotions.get('LABEL_0', 0) + 
                0.1 * emotions.get('LABEL_2', 0)
            )
            
            # Threat Analysis
            threat_result = self.threat_classifier(text)
            threat_scores_list = threat_result[0] if isinstance(threat_result[0], list) else threat_result
            threat_scores_dict = {item['label']: item['score'] for item in threat_scores_list}
            threat_score = sum(threat_scores_dict.get(label, 0) for label in self.threat_labels)
            
            # Urgency Analysis
            urgency_result = self.urgency_classifier(text, candidate_labels=self.urgency_labels)
            urgency_score = urgency_result['scores'][urgency_result['labels'].index("Urgent")]
            
            # Ensure all scores are floats
            threat_score = float(threat_score) if threat_score is not None else 0.0
            urgency_score = float(urgency_score) if urgency_score is not None else 0.0
            emotion_score = float(emotion_score) if emotion_score is not None else 0.0
            
            return {
                'emotion_score': emotion_score,
                'threat_score': threat_score,
                'urgency_score': urgency_score,
                'details': {
                    'emotions': emotions,
                    'threat_scores': threat_scores_dict,
                    'urgency_result': urgency_result
                }
            }
            
        except Exception as e:
            logger.error(f"Error in layer 2 analysis: {str(e)}")
            return {
                'emotion_score': 0.0,
                'threat_score': 0.0,
                'urgency_score': 0.0,
                'details': {'error': str(e)}
            }
    
    def analyze_text_layer3(self, text: str) -> dict:
        """
        Layer 3: Groq LLM-based classification
        """
        try:
            groq_result = self.groq_classifier.classify_message(text)
            
            # Convert classification to probability
            if groq_result['classification'] == 'spam':
                spam_probability = groq_result['confidence']
            elif groq_result['classification'] == 'ham':
                spam_probability = 1 - groq_result['confidence']
            else:
                spam_probability = 0.5
            
            return {
                'groq_classification': groq_result['classification'],
                'groq_confidence': groq_result['confidence'],
                'spam_probability': spam_probability,
                'details': groq_result
            }
            
        except Exception as e:
            logger.error(f"Error in layer 3 analysis: {str(e)}")
            return {
                'groq_classification': 'error',
                'groq_confidence': 0.0,
                'spam_probability': 0.5,
                'details': {'error': str(e)}
            }
    
    def calculate_final_phishing_score(self, layer1_result: dict, layer2_result: dict, layer3_result: dict) -> float:
        """
        Calculate final phishing score combining all three layers
        """
        # Layer 1 contribution (spam probability from your model)
        layer1_score = layer1_result.get('phishing_probability', 0.5)
        
        # Layer 2 contribution (weighted combination of emotion, threat, urgency)
        layer2_score = (
            0.35 * layer2_result.get('threat_score', 0.0) +
            0.35 * layer2_result.get('urgency_score', 0.0) +
            0.30 * layer2_result.get('emotion_score', 0.0)
        )
        
        # Layer 3 contribution (Groq spam probability)
        layer3_score = layer3_result.get('spam_probability', 0.5)
        
        # Final ensemble with updated weights (0.25 for layer1, 0.25 for layer2, 0.5 for layer3)
        final_score = 0.20 * layer1_score + 0.20 * layer2_score + 0.60 * layer3_score
        
        return min(max(final_score, 0.0), 1.0)  # Ensure score is between 0 and 1
    
    def analyze_text_complete(self, text: str) -> dict:
        """
        Complete text analysis combining all three layers
        """
        try:
            # Use fallback if models aren't loaded
            if not self.models_loaded:
                logger.info("Using fallback analysis (Groq only)")
                return self.analyze_text_simple(text)
            
            # Full analysis with all models
            # Layer 1 Analysis
            layer1_result = self.analyze_text_layer1(text)
            
            # Layer 2 Analysis
            layer2_result = self.analyze_text_layer2(text)
            
            # Layer 3 Analysis
            layer3_result = self.analyze_text_layer3(text)
            
            # Calculate final phishing score
            final_phishing_score = self.calculate_final_phishing_score(layer1_result, layer2_result, layer3_result)
            
            # Determine final classification
            is_phishing = final_phishing_score > 0.5
            confidence = abs(final_phishing_score - 0.5) * 2  # Scale to 0-1
            
            return {
                'is_phishing': is_phishing,
                'phishing_score': final_phishing_score,
                'confidence': confidence,
                'classification': 'phishing' if is_phishing else 'legitimate',
                'layer1_result': layer1_result,
                'layer2_result': layer2_result,
                'layer3_result': layer3_result,
                'analysis_details': {
                    'emotion_score': layer2_result.get('emotion_score', 0.0),
                    'threat_score': layer2_result.get('threat_score', 0.0),
                    'urgency_score': layer2_result.get('urgency_score', 0.0),
                    'groq_classification': layer3_result.get('groq_classification', 'unknown'),
                    'groq_confidence': layer3_result.get('groq_confidence', 0.0),
                    'bert_contribution': layer1_result.get('details', {}).get('bert_probs', {}),
                    'zero_shot_contribution': layer1_result.get('details', {}).get('zero_shot_probs', {}),
                    'layer_contributions': {
                        'layer1_weight': 0.20,
                        'layer2_weight': 0.20,
                        'layer3_weight': 0.60,
                        'layer1_score': layer1_result.get('phishing_probability', 0.5),
                        'layer2_score': (
                            0.35 * layer2_result.get('threat_score', 0.0) +
                            0.35 * layer2_result.get('urgency_score', 0.0) +
                            0.30 * layer2_result.get('emotion_score', 0.0)
                        ),
                        'layer3_score': layer3_result.get('spam_probability', 0.5)
                    }
                },
                'fallback_mode': False
            }
            
        except Exception as e:
            logger.error(f"Error in complete text analysis: {str(e)}")
            logger.info("Attempting fallback analysis")
            
            # Try fallback analysis
            try:
                return self.analyze_text_simple(text)
            except Exception as fallback_error:
                logger.error(f"Fallback analysis also failed: {str(fallback_error)}")
                return {
                    'is_phishing': False,
                    'phishing_score': 0.5,
                    'confidence': 0.0,
                    'classification': 'unknown',
                    'error': str(e),
                    'fallback_error': str(fallback_error)
                }
    
    def analyze_text_simple(self, text: str) -> dict:
        """
        Simple text analysis using only Groq API when full models aren't loaded
        """
        try:
            # Use only Groq for analysis
            groq_result = self.groq_classifier.classify_message(text)
            
            # Convert to standard format
            is_phishing = groq_result['classification'] == 'spam'
            phishing_score = groq_result['confidence'] if is_phishing else 1 - groq_result['confidence']
            
            return {
                'is_phishing': is_phishing,
                'phishing_score': phishing_score,
                'confidence': groq_result['confidence'],
                'classification': 'phishing' if is_phishing else 'legitimate',
                'layer1_result': {
                    'label': groq_result['classification'],
                    'score': groq_result['confidence'],
                    'phishing_probability': phishing_score,
                    'details': {'groq_only': True}
                },
                'layer2_result': {
                    'emotion_score': 0.0,
                    'threat_score': 0.0,
                    'urgency_score': 0.0,
                    'details': {'groq_only': True}
                },
                'layer3_result': {
                    'groq_classification': groq_result['classification'],
                    'groq_confidence': groq_result['confidence'],
                    'spam_probability': phishing_score,
                    'details': groq_result
                },
                'analysis_details': {
                    'emotion_score': 0.0,
                    'threat_score': 0.0,
                    'urgency_score': 0.0,
                    'groq_classification': groq_result['classification'],
                    'groq_confidence': groq_result['confidence'],
                    'bert_contribution': {'groq_only': True},
                    'zero_shot_contribution': {'groq_only': True},
                    'layer_contributions': {
                        'layer1_weight': 0.0,
                        'layer2_weight': 0.0,
                        'layer3_weight': 1.0,
                        'layer1_score': 0.0,
                        'layer2_score': 0.0,
                        'layer3_score': phishing_score
                    }
                },
                'fallback_mode': True,
                'reason': groq_result.get('reason', 'Groq API analysis')
            }
            
        except Exception as e:
            logger.error(f"Error in simple text analysis: {str(e)}")
            return {
                'is_phishing': False,
                'phishing_score': 0.5,
                'confidence': 0.0,
                'classification': 'unknown',
                'error': str(e),
                'fallback_mode': True
            }

# Create a singleton instance
text_analysis_service = TextAnalysisService()