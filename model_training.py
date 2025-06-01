import pandas as pd
import numpy as np
import sqlite3
import os
import time
from datetime import datetime
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_auc_score, precision_recall_curve
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from feature_extraction import extract_features

# Create database for URL history if it doesn't exist
def init_db():
    conn = sqlite3.connect('phishing_history.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS url_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            check_date TIMESTAMP NOT NULL,
            user_feedback TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

# Function to retrain model with user feedback
def retrain_model_with_feedback():
    if not os.path.exists('phishing_history.db'):
        print("No feedback database found. Skipping retraining.")
        return False
        
    # Load existing model
    if os.path.exists("model.pkl"):
        model = joblib.load("model.pkl")
    else:
        print("No existing model found. Cannot retrain.")
        return False
    
    # Load feedback data from database
    conn = sqlite3.connect('phishing_history.db')
    df = pd.read_sql('''
        SELECT url, prediction, user_feedback 
        FROM url_checks 
        WHERE user_feedback IS NOT NULL
    ''', conn)
    conn.close()
    
    if df.empty:
        print("No feedback data available for retraining.")
        return False
    
    # Process feedback data
    new_training_data = []
    new_labels = []
    
    for _, row in df.iterrows():
        # If user reported incorrect prediction
        if row['user_feedback'] != row['prediction']:
            features = extract_features(row['url'])
            new_training_data.append(features)
            new_labels.append(1 if row['user_feedback'] == 'Phishing' else 0)
    
    if new_training_data:
        # Update model with new data
        model.fit(new_training_data, new_labels)
        joblib.dump(model, "model.pkl")
        print(f"Model updated with {len(new_training_data)} new samples")
        return True
    else:
        print("No conflicting feedback found for retraining.")
        return False

# Main training function
def train_model():
    print("Starting model training...")
    start_time = time.time()
    
    # Load datasets - fix path to use current directory
    try:
        legitimate = pd.read_csv("dataset/legitimate_urls.txt", header=None, names=["url"])
        phishing = pd.read_csv('dataset/1000-phishing.txt', delimiter='\t', header=None, names=["url"])
    except FileNotFoundError:
        # Try alternate path if the first one fails
        legitimate = pd.read_csv("C:/Users/Tejus Kapoor/Desktop/projects/aa/dataset/legitimate_urls.txt", header=None, names=["url"])
        phishing = pd.read_csv('C:/Users/Tejus Kapoor/Desktop/projects/aa/dataset/1000-phishing.txt', delimiter='\t', header=None, names=["url"])

    print(f"Loaded {len(legitimate)} legitimate URLs and {len(phishing)} phishing URLs")

    # Label datasets
    legitimate["label"] = 0
    phishing["label"] = 1

    # Combine and shuffle datasets
    data = pd.concat([legitimate, phishing]).sample(frac=1).reset_index(drop=True)

    # Extract features and labels
    print("Extracting features...")
    data["features"] = data["url"].apply(extract_features)
    X = list(data["features"])
    y = list(data["label"])

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"Training set: {len(X_train)} samples, Test set: {len(X_test)} samples")

    # Try multiple models
    models = {
        'RandomForest': RandomForestClassifier(random_state=42),
        'GradientBoosting': GradientBoostingClassifier(random_state=42)
    }

    # Hyperparameter tuning
    param_grids = {
        'RandomForest': {
            'n_estimators': [100, 200],
            'max_depth': [None, 20],
            'min_samples_split': [2, 5],
            'class_weight': [None, 'balanced']
        },
        'GradientBoosting': {
            'n_estimators': [100, 200],
            'max_depth': [3, 5],
            'learning_rate': [0.1, 0.2]
        }
    }

    best_model = None
    best_score = 0
    best_model_name = ""

    for name, model in models.items():
        print(f"\nTraining {name}...")
        grid_search = GridSearchCV(model, param_grids[name], cv=5, scoring='roc_auc', n_jobs=-1)
        grid_search.fit(X_train, y_train)
        
        y_pred = grid_search.predict(X_test)
        y_proba = grid_search.predict_proba(X_test)[:, 1]
        
        accuracy = accuracy_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_proba)
        
        print(f"{name} - Best params: {grid_search.best_params_}")
        print(f"{name} - Accuracy: {accuracy:.4f}, AUC: {auc:.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        # Calculate confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        print("\nConfusion Matrix:")
        print(cm)
        
        # Track best model
        if auc > best_score:
            best_score = auc
            best_model = grid_search.best_estimator_
            best_model_name = name

    print(f"\nBest model: {best_model_name} with AUC: {best_score:.4f}")
    print(f"Training completed in {time.time() - start_time:.2f} seconds")

    # Save the best model
    joblib.dump(best_model, "model.pkl")
    print("Model saved as model.pkl")
    
    return best_model

# Initialize database and train model if this script is run directly
if __name__ == "__main__":
    init_db()
    train_model()