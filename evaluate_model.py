import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

# Load model and test data
model = joblib.load('models/final_model.pkl')
test = pd.read_csv('data/test_processed.csv')

X_test = test.drop(columns=['label_cat'])
y_test = test['label_cat']

# Make predictions
y_pred = model.predict(X_test)

# Evaluate
print(classification_report(y_test, y_pred))
print(confusion_matrix(y_test, y_pred))
