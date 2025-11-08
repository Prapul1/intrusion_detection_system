import pandas as pd

train = pd.read_csv('processed/train_processed.csv')
print(train.columns.tolist())
