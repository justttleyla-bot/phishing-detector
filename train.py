import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier
import joblib

# Load dataset
df = pd.read_csv('phishing.csv')

# Drop Index column
df = df.drop(columns=['Index'])

# Features and target
X = df.drop(columns=['class'])
y = df['class']

# Convert target: -1 (phishing) -> 0, 1 (legitimate) -> 1
y = y.map({-1: 0, 1: 1})

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = XGBClassifier(n_estimators=100, random_state=42, eval_metric='logloss')
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy * 100:.2f}%")
print("\nDetailed Report:")
print(classification_report(y_test, y_pred, target_names=['Phishing', 'Legitimate']))

# Save model
joblib.dump(model, 'model.pkl')
print("\nModel saved as model.pkl")