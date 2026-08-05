"""
predictor.py
============
Hugging Face DistilBERT inference engine for 48 attack categories.
Loads model and tokenizer ONCE at startup.
"""

import os
import torch
from typing import Tuple, Dict, Any, List
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
from app.config import MODEL_DIR
from app.logger import logger

class AttackPredictor:
    """Inference engine wrapper around fine-tuned DistilBERT attack classifier."""

    def __init__(self, model_dir: str = MODEL_DIR):
        self.model_dir = model_dir
        self.tokenizer = None
        self.model = None
        self.classifier = None
        self.id2label = {}
        self.label2id = {}
        self.is_loaded = False
        self._load_model()

    def _load_model(self):
        """Load HuggingFace model and tokenizer into memory once at startup."""
        if not os.path.exists(self.model_dir):
            logger.error(f"Model directory not found at: {self.model_dir}")
            raise FileNotFoundError(f"Trained model directory missing at {self.model_dir}")

        logger.info(f"Loading HuggingFace DistilBERT model from '{self.model_dir}'...")

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_dir)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_dir)
            self.model.eval()

            # Apply CPU Dynamic Quantization for ultra-fast VPS CPU inference if on CPU
            if not torch.cuda.is_available():
                logger.info("Applying INT8 dynamic quantization for CPU optimization...")
                self.model = torch.quantization.quantize_dynamic(
                    self.model, {torch.nn.Linear}, dtype=torch.qint8
                )

            device = 0 if torch.cuda.is_available() else -1
            self.classifier = pipeline(
                "text-classification",
                model=self.model,
                tokenizer=self.tokenizer,
                top_k=3,
                device=device
            )

            self.id2label = self.model.config.id2label
            self.label2id = self.model.config.label2id
            self.is_loaded = True

            logger.info(
                f"Model successfully loaded! Support {len(self.id2label)} attack classes on device {'GPU' if device == 0 else 'CPU'}."
            )
        except Exception as e:
            logger.critical(f"Failed to load AI model: {e}")
            raise e

    def predict(self, clean_text: str) -> Tuple[str, float, List[Dict[str, Any]]]:
        """
        Classify a single cleaned log line/text.
        
        Returns:
            Tuple[prediction_label, confidence_score, top3_list]
        """
        if not self.is_loaded or not self.classifier:
            raise RuntimeError("Model is not initialized.")

        if not clean_text or not clean_text.strip():
            return "Benign", 0.9999, [{"label": "Benign", "score": 0.9999}]

        try:
            # Truncate string to max 512 chars for safety before tokenizer
            truncated_text = clean_text[:512]
            results = self.classifier(truncated_text)[0]

            best_match = results[0]
            prediction = best_match["label"]
            confidence = float(best_match["score"])

            top3 = [
                {"label": item["label"], "score": round(float(item["score"]), 4)}
                for item in results
            ]

            return prediction, confidence, top3
        except Exception as e:
            logger.error(f"Inference error for text '{clean_text[:50]}...': {e}")
            return "Benign", 0.50, [{"label": "Benign", "score": 0.50}]

# Global singleton predictor instance initialized once
predictor = AttackPredictor()
