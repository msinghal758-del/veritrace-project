"""
VeriTrace - Phase 3: Machine Learning Training Pipeline
Dataset: Official UNSW-NB15 Cybersecurity Dataset (175,341 records)
Task: Multiclass Attack Category Classification (attack_cat)
Model: RandomForestClassifier with ColumnTransformer Preprocessing Pipeline
"""

import os
import sys
import time
import json
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "datasets", "UNSW_NB15_training-set.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_SAVE_PATH = os.path.join(MODELS_DIR, "veritrace_model.joblib")
METRICS_SAVE_PATH = os.path.join(MODELS_DIR, "metrics.json")


def run_pipeline():
    print("=" * 70)
    print("  VERITRACE PHASE 3: REAL ML MODEL TRAINING & EVALUATION")
    print("=" * 70)

    # ---------------------------------------------------------
    # 1. LOAD DATASET
    # ---------------------------------------------------------
    print(f"\n[1/5] Loading official UNSW-NB15 dataset from:\n      {DATASET_PATH}")
    start_time = time.time()
    df = pd.read_csv(DATASET_PATH)
    print(f"      Loaded {df.shape[0]:,} records with {df.shape[1]} columns in {time.time() - start_time:.2f}s.")

    # Clean string columns
    df['attack_cat'] = df['attack_cat'].astype(str).str.strip()
    df['proto'] = df['proto'].astype(str).str.strip()
    df['service'] = df['service'].astype(str).str.strip()
    df['state'] = df['state'].astype(str).str.strip()

    # ---------------------------------------------------------
    # 2. FEATURE SELECTION & TARGET SPECIFICATION
    # ---------------------------------------------------------
    print("\n[2/5] Defining features and target variable...")
    # Exclude id and label to prevent target leakage
    drop_cols = ['id', 'label', 'attack_cat']
    X = df.drop(columns=drop_cols)
    y = df['attack_cat']

    cat_cols = ['proto', 'service', 'state']
    num_cols = [c for c in X.columns if c not in cat_cols]

    print(f"      Target: attack_cat ({y.nunique()} distinct classes)")
    print(f"      Excluded Columns: {drop_cols} (preventing leakage)")
    print(f"      Input Features: {len(X.columns)} total ({len(num_cols)} numerical, {len(cat_cols)} categorical)")

    # ---------------------------------------------------------
    # 3. STRATIFIED TRAIN / TEST SPLIT (80% Train, 20% Test)
    # ---------------------------------------------------------
    print("\n[3/5] Performing stratified 80/20 train-test split (random_state=42)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )
    print(f"      Training Set : {len(X_train):,} samples (80.0%)")
    print(f"      Testing Set  : {len(X_test):,} samples (20.0%)")

    # ---------------------------------------------------------
    # 4. BUILD PIPELINE & TRAIN MODEL
    # ---------------------------------------------------------
    print("\n[4/5] Building ColumnTransformer and RandomForestClassifier pipeline...")

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), num_cols),
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), cat_cols),
        ]
    )

    model_pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(
            n_estimators=100,
            max_depth=25,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        ))
    ])

    print("      Training RandomForestClassifier on 140,272 actual training records...")
    train_start = time.time()
    model_pipeline.fit(X_train, y_train)
    train_duration = time.time() - train_start
    print(f"      [OK] Training completed in {train_duration:.2f} seconds.")

    # ---------------------------------------------------------
    # 5. MODEL EVALUATION ON UNSEEN TEST SET (20%)
    # ---------------------------------------------------------
    print("\n[5/5] Evaluating model on unseen 20% test partition (35,069 records)...")
    eval_start = time.time()
    y_pred = model_pipeline.predict(X_test)
    eval_duration = time.time() - eval_start
    print(f"      Inference completed in {eval_duration:.2f} seconds.")

    # Calculate exact mathematical evaluation metrics
    acc = float(accuracy_score(y_test, y_pred))
    p_macro = float(precision_score(y_test, y_pred, average='macro', zero_division=0))
    p_weighted = float(precision_score(y_test, y_pred, average='weighted', zero_division=0))
    r_macro = float(recall_score(y_test, y_pred, average='macro', zero_division=0))
    r_weighted = float(recall_score(y_test, y_pred, average='weighted', zero_division=0))
    f1_m = float(f1_score(y_test, y_pred, average='macro', zero_division=0))
    f1_w = float(f1_score(y_test, y_pred, average='weighted', zero_division=0))

    classes = sorted(list(y.unique()))
    cm = confusion_matrix(y_test, y_pred, labels=classes).tolist()
    clf_report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

    print("\n" + "=" * 70)
    print("  GENUINE MODEL EVALUATION METRICS (TEST SET: 35,069 RECORDS)")
    print("=" * 70)
    print(f"  Overall Accuracy    : {acc * 100:.2f}%")
    print(f"  Macro Precision     : {p_macro * 100:.2f}%")
    print(f"  Weighted Precision  : {p_weighted * 100:.2f}%")
    print(f"  Macro Recall        : {r_macro * 100:.2f}%")
    print(f"  Weighted Recall     : {r_weighted * 100:.2f}%")
    print(f"  Macro F1-Score      : {f1_m * 100:.2f}%")
    print(f"  Weighted F1-Score   : {f1_w * 100:.2f}%")
    print("=" * 70)

    print("\nPer-Class Performance Summary:")
    print(f"  {'Attack Class':<18} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Test Support'}")
    print("  " + "-" * 65)
    for c in classes:
        if c in clf_report:
            p = clf_report[c]['precision'] * 100
            r = clf_report[c]['recall'] * 100
            f = clf_report[c]['f1-score'] * 100
            s = int(clf_report[c]['support'])
            print(f"  {c:<18} | {p:>8.2f}% | {r:>8.2f}% | {f:>8.2f}% | {s:>10,}")

    # ---------------------------------------------------------
    # 6. SAVE MODEL AND METRICS
    # ---------------------------------------------------------
    os.makedirs(MODELS_DIR, exist_ok=True)

    print(f"\nSaving fitted model pipeline to:\n  {MODEL_SAVE_PATH}")
    joblib.dump(model_pipeline, MODEL_SAVE_PATH)
    file_size_mb = os.path.getsize(MODEL_SAVE_PATH) / (1024 * 1024)
    print(f"  [OK] Saved successfully ({file_size_mb:.2f} MB)")

    metrics_payload = {
        "dataset": "UNSW-NB15",
        "total_records": len(df),
        "train_records": len(X_train),
        "test_records": len(X_test),
        "model_type": "RandomForestClassifier",
        "parameters": {
            "n_estimators": 100,
            "max_depth": 25,
            "min_samples_split": 5,
            "random_state": 42
        },
        "features": {
            "numerical_features_count": len(num_cols),
            "numerical_features": num_cols,
            "categorical_features_count": len(cat_cols),
            "categorical_features": cat_cols,
            "excluded_features": drop_cols
        },
        "target_classes": classes,
        "evaluation": {
            "accuracy": acc,
            "precision_macro": p_macro,
            "precision_weighted": p_weighted,
            "recall_macro": r_macro,
            "recall_weighted": r_weighted,
            "f1_macro": f1_m,
            "f1_weighted": f1_w
        },
        "per_class_report": clf_report,
        "confusion_matrix": {
            "labels": classes,
            "matrix": cm
        },
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "training_duration_seconds": round(train_duration, 2),
        "evaluation_duration_seconds": round(eval_duration, 2)
    }

    print(f"\nSaving genuine evaluation metrics to:\n  {METRICS_SAVE_PATH}")
    with open(METRICS_SAVE_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)
    print("  [OK] Saved metrics.json successfully")

    print("\n[DONE] Phase 3 Machine Learning Pipeline Finished Successfully!")
    return metrics_payload


if __name__ == "__main__":
    run_pipeline()
