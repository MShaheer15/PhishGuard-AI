import pandas as pd
import pickle
import json
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import accuracy_score, classification_report

# Paths
DATASET_PATH = os.path.join(os.path.dirname(__file__), '../dataset/Phishing_Legitimate_full.csv')
MODEL_DIR = os.path.join(os.path.dirname(__file__), '../ml')
MODEL_PATH = os.path.join(MODEL_DIR, 'phishing_model.pkl')
FEATURES_PATH = os.path.join(MODEL_DIR, 'features.json')

def train():
    print("Loading dataset...")
    df = pd.read_csv(DATASET_PATH)
    
    # Preprocessing
    # Drop ID
    if 'id' in df.columns:
        df = df.drop(columns=['id'])
    
    # Handle missing values
    df = df.fillna(0)
        
    # Define Target
    target = 'CLASS_LABEL'
    X = df.drop(columns=[target])
    y = df[target]
    
    # Save Feature Names
    feature_names = list(X.columns)
    
    # Train/Test Split
    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Hyperparameter Tuning with GridSearchCV
    print("Running hyperparameter search...")
    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [None, 20, 30],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2],
    }
    
    base_clf = RandomForestClassifier(random_state=42, n_jobs=-1)
    grid_search = GridSearchCV(base_clf, param_grid, cv=3, scoring='accuracy', n_jobs=-1, verbose=1)
    grid_search.fit(X_train, y_train)
    
    clf = grid_search.best_estimator_
    print(f"\nBest Parameters: {grid_search.best_params_}")
    print(f"Best CV Accuracy: {grid_search.best_score_:.4f}")
    
    # Cross-Validation on full training set
    print("\nRunning 5-fold cross-validation...")
    cv_scores = cross_val_score(clf, X_train, y_train, cv=5, scoring='accuracy')
    print(f"CV Scores: {cv_scores}")
    print(f"Mean CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Evaluate on Test Set
    print("\nEvaluating on test set...")
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Test Accuracy: {accuracy:.4f}")
    print(classification_report(y_test, y_pred))
    
    # Feature Importance
    print("\n--- Top 15 Most Important Features ---")
    importances = clf.feature_importances_
    importance_df = pd.DataFrame({
        'Feature': feature_names,
        'Importance': importances
    }).sort_values('Importance', ascending=False)
    
    for i, row in importance_df.head(15).iterrows():
        bar = '█' * int(row['Importance'] * 100)
        print(f"  {row['Feature']:40s} {row['Importance']:.4f} {bar}")
    
    # Save Artifacts
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
        
    print(f"\nSaving model to {MODEL_PATH}...")
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(clf, f)
        
    print(f"Saving feature list to {FEATURES_PATH}...")
    with open(FEATURES_PATH, 'w') as f:
        json.dump(feature_names, f)
        
    print("Done!")

if __name__ == '__main__':
    train()
