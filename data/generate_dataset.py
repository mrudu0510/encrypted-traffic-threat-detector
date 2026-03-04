# Dataset Generator

import pandas as pd
import numpy as np

class DatasetGenerator:
    def __init__(self, num_samples:int, num_features:int):
        self.num_samples = num_samples
        self.num_features = num_features

    def generate(self):
        # Generate random data
        data = np.random.rand(self.num_samples, self.num_features)
        return pd.DataFrame(data, columns=[f'feature_{i}' for i in range(self.num_features)])

if __name__ == '__main__':
    generator = DatasetGenerator(1000, 10)
    dataset = generator.generate()
    dataset.to_csv('generated_dataset.csv', index=False)