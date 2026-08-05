"""
evaluate_model.py
=================
Evaluation Suite for Enterprise VPS Security AI (48 Classes).
Calculates Accuracy, Precision, Recall, F1-Score, Classification Report,
and saves predictions.csv and misclassified_samples.csv.
"""

import pandas as pd
import numpy as np
import os
import torch
from transformers import pipeline, AutoModelForSequenceClassification, AutoTokenizer
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report
import warnings
warnings.filterwarnings("ignore")

MODEL_DIR = "./trained_model"
TEST_DATASET = "./enterprise_security_dataset.csv"

def evaluate_model():
    print(f"Loading test dataset from: {TEST_DATASET}...")
    df = pd.read_csv(TEST_DATASET)
    df = df.dropna(subset=['text', 'label'])
    df['text'] = df['text'].astype(str)
    print(f"Dataset loaded. Total samples: {len(df)} across {df['label'].nunique()} classes.")
    
    print(f"\nLoading model from {MODEL_DIR}...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    
    classifier = pipeline(
        "text-classification",
        model=model,
        tokenizer=tokenizer,
        top_k=1,
        device=-1  # Use CPU
    )
    
    print("\nRunning predictions across dataset...")
    
    batch_size = 128
    all_predictions = []
    
    for i in range(0, len(df), batch_size):
        batch_texts = df['text'].iloc[i:i+batch_size].tolist()
        batch_preds = classifier(batch_texts)
        all_predictions.extend([p[0] for p in batch_preds])
        if i % (batch_size * 5) == 0 and i > 0:
            print(f"Processed {i}/{len(df)} samples...")
            
    print(f"Processed {len(df)}/{len(df)} samples.")
    
    df['predicted_label'] = [p['label'] for p in all_predictions]
    df['confidence'] = [p['score'] for p in all_predictions]
    
    y_true = df['label'].tolist()
    y_pred = df['predicted_label'].tolist()
    
    # Save predictions
    df.to_csv("predictions.csv", index=False)
    print("\nSaved all predictions to predictions.csv")
    
    # Save misclassified samples
    misclassified = df[df['label'] != df['predicted_label']]
    misclassified.to_csv("misclassified_samples.csv", index=False)
    print(f"Saved {len(misclassified)} misclassified samples to misclassified_samples.csv")
    
    # Calculate Metrics
    accuracy = accuracy_score(y_true, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='weighted', zero_division=0)
    
    print("\n" + "="*60)
    print("MODEL EVALUATION METRICS (48 CLASSES)")
    print("="*60)
    print(f"Accuracy : {accuracy*100:.2f}%")
    print(f"Precision: {precision*100:.2f}%")
    print(f"Recall   : {recall*100:.2f}%")
    print(f"F1-Score : {f1*100:.2f}%")
    
    print("\n" + "="*60)
    print("CLASSIFICATION REPORT")
    print("="*60)
    
    report = classification_report(y_true, y_pred, zero_division=0, output_dict=True)
    print(classification_report(y_true, y_pred, zero_division=0))
    
    class_metrics = []
    for label, metrics in report.items():
        if label not in ['accuracy', 'macro avg', 'weighted avg']:
            class_metrics.append({
                'label': label,
                'f1': metrics['f1-score'],
                'support': metrics['support']
            })
            
    class_metrics.sort(key=lambda x: x['f1'])
    
    print("\n" + "="*60)
    print("WORST PERFORMING CLASSES (Bottom 5)")
    print("="*60)
    for i, item in enumerate(class_metrics[:5]):
        print(f"{i+1}. {item['label']:<32} F1: {item['f1']*100:.2f}%  (samples: {item['support']})")
        
    print("\nEvaluation complete!")

if __name__ == "__main__":
    evaluate_model()
