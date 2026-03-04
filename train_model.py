# train_model.py
import pandas as pd
from models.model_trainer import train_model
from config import DATABASE_URI

# Load data
# Assuming data is properly formatted and available in a suitable format
train_data = pd.read_csv('data/train_data.csv')

# Train the model
model = train_model(train_data)
