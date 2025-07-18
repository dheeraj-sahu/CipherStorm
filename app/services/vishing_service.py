import numpy as np
import pickle
import librosa
import whisper
import shutil
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from typing import List, Dict, Any
import tempfile
import os
from groq import Groq
import json

class VishingDetectionService:
    def __init__(self, groq_api_key=None):
        # Initialize Groq client
        self.groq_client = Groq(
            api_key=groq_api_key or os.environ.get("GROQ_API_KEY")
        )
        
        # Load emotion classification model
        self.em_clf = pipeline("text-classification", model="hamzawaheed/emotion-classification-model", return_all_scores=True, truncation=True, max_length=512)
        
        # Load threat classification model
        model_name = "HiddenKise/Kaviel-threat-text-classifier"
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        self.threat_clf = pipeline("text-classification", model=model, tokenizer=tokenizer, return_all_scores=True, truncation=True, max_length=512)
        
        # Load urgency classifier
        self.urgency_classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli", truncation=True, max_length=512)
        
        # Load Whisper model for transcription
        self.whisper_model = whisper.load_model("base")
        
        # Create recordings directory if it doesn't exist
        self.recordings_dir = "recordings"
        os.makedirs(self.recordings_dir, exist_ok=True)
        
        # Load trained models (you'll need to provide these)
        try:
            with open("app/ml_models/isolation_forest_pipeline.pkl", "rb") as f:
                self.isolation_pipeline = pickle.load(f)
        except FileNotFoundError:
            self.isolation_pipeline = None
            
        try:
            with open("app/ml_models/rfc_vishing_model.pkl", "rb") as f:
                self.rf_model = pickle.load(f)
        except FileNotFoundError:
            self.rf_model = None
        
        # Define weights for ensemble
        self.weight_model1 = 0.60  # groq ensemble
        self.weight_model2 = 0.15  # voice anomaly
        self.weight_model3 = 0.25  # RFC on text-based scores
        
        # Final classification labels
        self.labels = ["Legitimate", "Suspicious"]
        self.urgency_labels = ["Urgent", "Not Urgent"]
        self.threat_labels = ['Life Threat', 'Online Scam', 'Information Leakage']

    def groq_classify(self, text, model="llama3-70b-8192"):
        """
        Classify text using Groq API
        """
        prompt = f"""
You are a vishing detection system. Classify the following call transcript as either "Suspicious" or "Legitimate".

Call Transcript: "{text}"

Consider these as LEGITIMATE:
- Standard transaction notifications or alerts not demanding anything

Analyze the transcript for:
- Commands to press buttons or take immediate action
- Threats about account suspension or legal consequences
- Requests for personal information (SSN, passwords, card details)
- Impersonation of authorities (IRS, banks, police, tech support)
- Creating urgency or fear to pressure decisions
- Payment demands or unusual payment methods


Respond with ONLY a JSON object in this format:
{{
    "classification": "Suspicious" or "Legitimate",
    "confidence": 0.0-1.0,
    "reason": "brief explanation"
}}
"""

        try:
            chat_completion = self.groq_client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                model=model,
                temperature=0.1,
                max_tokens=300,
                top_p=1,
                stream=False,
                stop=None,
            )
            
            response_text = chat_completion.choices[0].message.content.strip()
            
            try:
                result = json.loads(response_text)
                classification = result.get("classification", "Legitimate")
                confidence = result.get("confidence", 0.5)
                
                # Convert to expected format
                if classification == "Suspicious":
                    return {"Suspicious": confidence, "Legitimate": 1 - confidence}
                else:
                    return {"Legitimate": confidence, "Suspicious": 1 - confidence}
                    
            except json.JSONDecodeError:
                # Fallback parsing
                if any(word in response_text.lower() for word in ["vishing", "scam", "fraud", "suspicious"]):
                    return {"Suspicious": 0.7, "Legitimate": 0.3}
                else:
                    return {"Legitimate": 0.7, "Suspicious": 0.3}
                    
        except Exception as e:
            print(f"Groq API Error: {str(e)}")
            return {"Legitimate": 0.5, "Suspicious": 0.5}

    def transcribe_audio(self, audio_path: str) -> str:
        """Transcribe audio using Whisper AI"""
        try:
            result = self.whisper_model.transcribe(audio_path)
            return result["text"]
        except Exception as e:
            print(f"Error transcribing audio {audio_path}: {e}")
            return "Transcription failed"

    def save_audio_recording(self, audio_path: str, user_id: int) -> str:
        """Save audio recording to recordings directory"""
        try:
            from datetime import datetime
            from app.models.constant import IST
            timestamp = datetime.now(IST).strftime("%Y%m%d_%H%M%S")
            file_extension = os.path.splitext(audio_path)[1]
            new_filename = f"user_{user_id}_{timestamp}{file_extension}"
            new_path = os.path.join(self.recordings_dir, new_filename)
            
            shutil.copy2(audio_path, new_path)
            return new_path
        except Exception as e:
            print(f"Error saving audio recording: {e}")
            return audio_path

    def sigmoid(self, x):
        """Utility: sigmoid function to map anomaly score into (0, 1)"""
        return 1 / (1 + np.exp(-x))

    def normalize_dict(self, d):
        """Normalize a dict so its values sum to 1"""
        total = sum(d.values())
        return {k: v / total if total != 0 else 0 for k, v in d.items()}

    def extract_voice_features(self, audio_path: str, transcript: str) -> List[float]:
        """
        Extract 18-dimensional feature vector from audio and transcript.
        Returns a list [mean_pitch, pitch_variance, mean_energy, words_per_sec, urgency_score, mfcc_1...mfcc_13]
        """
        try:
            # Load audio
            y, sr = librosa.load(audio_path, sr=None)

            # Pitch (f0)
            f0 = librosa.yin(y, fmin=50, fmax=500)
            mean_pitch = f0.mean() if len(f0) > 0 else 0.0
            pitch_variance = f0.var() if len(f0) > 0 else 0.0

            # Energy
            rms = librosa.feature.rms(y=y)[0]
            mean_energy = rms.mean() if len(rms) > 0 else 0.0

            # Words per second
            words = transcript.split()
            duration = librosa.get_duration(y=y, sr=sr)
            words_per_sec = len(words) / duration if duration > 0 else 0.0

            # Urgency score using zero-shot classification
            urgency_result = self.urgency_classifier(transcript, candidate_labels=self.urgency_labels)
            urgency_score = urgency_result['scores'][urgency_result['labels'].index("Urgent")]

            # MFCCs
            mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
            mfcc_mean = mfccs.mean(axis=1).tolist() if mfccs.shape[1] > 0 else [0.0] * 13

            # Final 18D vector
            return [mean_pitch, pitch_variance, mean_energy, words_per_sec, urgency_score] + mfcc_mean

        except Exception as e:
            print(f"Error processing {audio_path}: {e}")
            return [0.0] * 18  # fallback

    def calculate_text_scores(self, text: str) -> List[float]:
        """Calculate text-based scores for emotion, threat, urgency, and vishing"""
        
        # Emotion score
        em_res = self.em_clf(text)
        if isinstance(em_res[0], list):
            em_scores = em_res[0]
        else:
            em_scores = em_res
        
        emotions = {item['label']: item['score'] for item in em_scores}
        emotion_score = (emotions.get('LABEL_3', 0) + emotions.get('LABEL_4', 0) + 
                        0.5 * emotions.get('LABEL_5', 0) + 0.3 * emotions.get('LABEL_0', 0) + 
                        0.1 * emotions.get('LABEL_2', 0))
        
        # Threat score
        th_res = self.threat_clf(text)
        scores_list = th_res[0]
        scores_dict = {item['label']: item['score'] for item in scores_list}
        threat_score = sum(scores_dict.get(label, 0) for label in self.threat_labels)
        
        # Urgency score
        result = self.urgency_classifier(text, candidate_labels=self.urgency_labels)
        urgency_score = result['scores'][result['labels'].index("Urgent")]
        
        # Vishing score
        vishing_score = 0.30 * threat_score + 0.35 * urgency_score + 0.35 * emotion_score
        
        return [threat_score, emotion_score, urgency_score , vishing_score]

    def ensemble_prediction(self, text_input: str, voice_features: List[float], text_scores: List[float]) -> Dict[str, Any]:
        """Main ensemble function"""
        
        # -------------------------------
        # Model 1: Groq Ensemble
        # -------------------------------
        groq1_scores = self.groq_classify(text_input, model="llama3-8b-8192")
        groq2_scores = self.groq_classify(text_input, model="llama3-70b-8192")

        model1_scores = {
            label: 0.2 * groq1_scores.get(label, 0.0) + 0.8 * groq2_scores.get(label, 0.0)
            for label in self.labels
        }

        # -------------------------------
        # Model 2: Isolation Forest
        # -------------------------------
        if self.isolation_pipeline:
            anomaly_score = self.isolation_pipeline.decision_function([voice_features])[0]
            legit_prob = self.sigmoid(anomaly_score)
        else:
            legit_prob = 0.5  # Default if model not available

        model2_scores = {
            "Legitimate": legit_prob,
            "Suspicious": 1 - legit_prob
        }

        # -------------------------------
        # Model 3: RFC on text-based scores
        # -------------------------------
        if self.rf_model:
            proba = self.rf_model.predict_proba([text_scores])[0]
            rf_labels = self.rf_model.classes_
            model3_scores = {
                "Legitimate": proba[rf_labels.tolist().index(0)] if 0 in rf_labels else 0.0,
                "Suspicious": proba[rf_labels.tolist().index(1)] if 1 in rf_labels else 0.0
            }
        else:
            model3_scores = {"Legitimate": 0.5, "Suspicious": 0.5}  # Default if model not available

        # -------------------------------
        # Final Ensemble
        # -------------------------------
        final_probs = {
            label: (self.weight_model1 * model1_scores.get(label, 0) +
                   self.weight_model2 * model2_scores.get(label, 0) +
                   self.weight_model3 * model3_scores.get(label, 0))
            for label in self.labels
        }

        final_label = max(final_probs, key=final_probs.get)
        final_score = final_probs[final_label]

        return {
            "label": final_label,
            "score": final_score,
            "details": {
                "groq_ensemble": model1_scores,
                "voice_model": model2_scores,
                "text_feature_model": model3_scores,
                "ensemble": final_probs
            }
        }

    def process_audio(self, audio_file_path: str, transcript: str = None, user_id: int = None) -> Dict[str, Any]:
        """Process audio file and return vishing detection results"""
    
        # Save audio recording to recordings directory
        if user_id:
            saved_audio_path = self.save_audio_recording(audio_file_path, user_id)
        else:
            saved_audio_path = audio_file_path

        # Check if transcript is provided or if it's a default/empty value
        # Treat 'string', empty strings, and other default values as no transcript
        if not transcript or transcript.strip().lower() in ["no transcript provided", "string", "none", "null", ""]:
            print(f"No valid transcript provided (received: '{transcript}'), using Whisper transcription...")
            transcript = self.transcribe_audio(audio_file_path)
            transcript_source = "whisper"
            print(f"Whisper transcription result: {transcript}")
        else:
            transcript_source = "user"
            print(f"Using user-provided transcript: {transcript}")

        # Extract voice features
        voice_features = self.extract_voice_features(audio_file_path, transcript)
        
        # Calculate text scores
        text_scores = self.calculate_text_scores(transcript)
        
        # Get ensemble prediction
        result = self.ensemble_prediction(transcript, voice_features, text_scores)
        
        return {
            "prediction": result,
            "voice_features": voice_features,
            "text_scores": {
                "threat_score": text_scores[0],
                "manipulative_emotion_score": text_scores[1], 
                "urgency_score": text_scores[2],
                "vishing_score": text_scores[3]
            },
            "transcript": transcript,
            "transcript_source": transcript_source,
            "saved_audio_path": saved_audio_path
        }

# Global instance
vishing_service = VishingDetectionService()