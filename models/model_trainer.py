# model_trainer.py
from sklearn.ensemble import RandomForestClassifier

def train_model(data):
    model = RandomForestClassifier()
    model.fit(data[['features']], data['target'])
    return model
