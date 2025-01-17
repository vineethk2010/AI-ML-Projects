#!/usr/bin/env python3
"""
Module Docstring
"""

# prediction.py
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import pickle

# Load the model
with open('rnn.pkl', 'rb') as f:
    model = pickle.load(f)

# Function to perform prediction on a separate dataset
def predict_on_holdout_dataset(dataset_path: str):
    holdout_data = pd.read_csv(dataset_path)

    X_holdout = holdout_data.drop('label', axis=1).values
    y_holdout = holdout_data['label'].values

    # Scale features
    scaler = MinMaxScaler()
    X_holdout = scaler.fit_transform(X_holdout)

    # Encode labels
    label_encoder = LabelEncoder()
    y_holdout = label_encoder.fit_transform(y_holdout)

    # Reshape X for LSTM input: (samples, timesteps, features)
    X_holdout = np.reshape(X_holdout, (X_holdout.shape[0], 1, X_holdout.shape[1]))

    # Make predictions
    predictions = model.predict(X_holdout)

    # Convert predictions to class labels
    predicted_classes = np.argmax(predictions, axis=1)

    # Map numerical labels back to original class labels
    predicted_labels = label_encoder.inverse_transform(predicted_classes)

    # Output the predictions
    holdout_data['Predicted_Label'] = predicted_labels
    print(holdout_data[['label', 'Predicted_Label']])

    return holdout_data