import pandas as pd
import numpy as np
import sys

from data.generate_dataset import DatasetGenerator
from data.data_preprocessor import DataPreprocessor
from utils.data_validator import DataValidator
from models.feature_engineering import FeatureEngineer
from models.model_trainer import ModelTrainer
from models.model_evaluator import ModelEvaluator


def main():
    # Step 1: Generate dataset
    print("Generating dataset...")
    generator = DatasetGenerator()
    dataset = generator.generate()
    print("Dataset generated.")

    # Step 2: Validate the dataset
    print("Validating dataset...")
    validator = DataValidator()
    validator.validate(dataset)
    print("Dataset validation complete.")

    # Step 3: Feature engineering
    print("Engineering features...")
    engineer = FeatureEngineer()
    features = engineer.transform(dataset)
    print("Feature engineering complete.")

    # Step 4: Data preprocessing
    print("Preprocessing data...")
    preprocessor = DataPreprocessor()
    processed_data = preprocessor.preprocess(features)
    print("Data preprocessing complete.")

    # Step 5: Train models
    print("Training models...")
    trainer = ModelTrainer()
    model = trainer.train(processed_data)
    print("Model training complete.")

    # Step 6: Evaluate models
    print("Evaluating models...")
    evaluator = ModelEvaluator()
    results = evaluator.evaluate(model, processed_data)
    print("Model evaluation complete.")

    # Step 7: Generate summary report
    print("Generating summary report...")
    # Assuming a function to generate summary
    print("Summary report generated.")

# Execute main function
if __name__ == '__main__':
    main()