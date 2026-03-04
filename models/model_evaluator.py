# model_evaluator.py
from sklearn.metrics import accuracy_score

def evaluate_model(model, X_test, y_test):
    predictions = model.predict(X_test)
    return accuracy_score(y_test, predictions)
